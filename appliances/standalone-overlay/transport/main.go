// Parto's stream adapter uses upstream Lyrebird obfs4; it implements no cryptography.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	pt "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/goptlib"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/transports/obfs4"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

const timingMode = 0

type config struct {
	Role      string `json:"role"`
	Listen    string `json:"listen"`
	Target    string `json:"target"`
	Source    string `json:"source"`
	Interface string `json:"interface"`
	Cert      string `json:"cert"`
	StateDir  string `json:"state_dir"`
}

func privateDirectory(path string) error {
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 || info.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		return errors.New("private state directory required")
	}
	return nil
}
func stateExists(path string) bool {
	info, err := os.Lstat(filepath.Join(path, "obfs4_state.json"))
	return err == nil && info.Mode().IsRegular() && info.Mode().Perm() == 0600 && info.Sys().(*syscall.Stat_t).Uid == uint32(os.Geteuid())
}
func serverFactory(path string, initialize bool) (*obfs4.Transport, error) {
	if err := privateDirectory(path); err != nil {
		return nil, err
	}
	if _, err := os.Lstat(filepath.Join(path, "obfs4_state.json")); err == nil && !stateExists(path) {
		return nil, errors.New("bridge identity permissions or type invalid")
	}
	if !initialize && !stateExists(path) {
		return nil, errors.New("persisted bridge identity missing")
	}
	return &obfs4.Transport{}, nil
}
func loadConfig(path string) (config, error) {
	var c config
	f, err := os.Open(path)
	if err != nil {
		return c, err
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, 16385))
	d.DisallowUnknownFields()
	if err = d.Decode(&c); err != nil {
		return c, err
	}
	var extra interface{}
	if d.Decode(&extra) != io.EOF {
		return c, errors.New("one configuration object required")
	}
	src := net.ParseIP(c.Source)
	if src == nil || src.To4() == nil || src.IsLoopback() || c.Interface != "eth0" {
		return c, errors.New("verified transport WAN required")
	}
	if c.Role == "hub" {
		if c.Listen != net.JoinHostPort(c.Source, "443") || c.Target != "127.0.0.1:4443" || c.StateDir != "/etc/parto/standalone/obfs4" {
			return c, errors.New("invalid Hub bridge configuration")
		}
	} else if c.Role == "spoke" {
		host, port, e := net.SplitHostPort(c.Target)
		if e != nil || net.ParseIP(host) == nil || net.ParseIP(host).To4() == nil || port != "443" || c.Listen != "127.0.0.1:3443" || c.StateDir != "" {
			return c, errors.New("invalid Spoke bridge configuration")
		}
	} else {
		return c, errors.New("invalid bridge role")
	}
	if len(c.Cert) != 70 {
		return c, errors.New("bridge descriptor required")
	}
	return c, nil
}
func relay(a, b net.Conn) {
	done := make(chan struct{}, 2)
	copyStream := func(dst, src net.Conn) { io.Copy(dst, src); done <- struct{}{} }
	go copyStream(a, b)
	go copyStream(b, a)
	<-done
	a.Close()
	b.Close()
	<-done
}
func serve(c config) error {
	transport := &obfs4.Transport{}
	args := pt.Args{}
	args.Add("iat-mode", strconv.Itoa(timingMode))
	var wrap func(net.Conn) (net.Conn, error)
	if c.Role == "hub" {
		if _, err := serverFactory(c.StateDir, false); err != nil {
			return err
		}
		sf, err := transport.ServerFactory(c.StateDir, &args)
		if err != nil {
			return err
		}
		cert, _ := sf.Args().Get("cert")
		if cert != c.Cert {
			return errors.New("bridge identity differs from signed invitation")
		}
		wrap = sf.WrapConn
	} else {
		args.Add("cert", c.Cert)
		cf, err := transport.ClientFactory("")
		if err != nil {
			return err
		}
		// ParseArgs creates a per-connection session key, so never reuse its result.
		wrap = func(_ net.Conn) (net.Conn, error) {
			parsed, err := cf.ParseArgs(&args)
			if err != nil {
				return nil, err
			}
			dialer := net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP(c.Source)}, Control: func(_, _ string, raw syscall.RawConn) error {
				var e error
				err := raw.Control(func(fd uintptr) {
					e = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, c.Interface)
				})
				if err != nil {
					return err
				}
				return e
			}}
			return cf.Dial("tcp4", c.Target, dialer.Dial, parsed)
		}
	}
	listener, err := net.Listen("tcp4", c.Listen)
	if err != nil {
		return err
	}
	defer listener.Close()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(signals)
	go func() { <-signals; listener.Close() }()
	slots := make(chan struct{}, 128)
	for {
		local, e := listener.Accept()
		if e != nil {
			return nil
		}
		select {
		case slots <- struct{}{}:
		default:
			local.Close()
			continue
		}
		go func() {
			defer func() { <-slots }()
			defer local.Close()
			if c.Role == "hub" {
				protected, err := wrap(local)
				if err != nil {
					return
				}
				defer protected.Close()
				backend, err := net.DialTimeout("tcp4", c.Target, 5*time.Second)
				if err != nil {
					return
				}
				defer backend.Close()
				relay(protected, backend)
			} else {
				protected, err := wrap(local)
				if err != nil {
					return
				}
				defer protected.Close()
				relay(local, protected)
			}
		}()
	}
}
func run() error {
	syscall.Umask(0077)
	if len(os.Args) < 2 {
		return errors.New("command required")
	}
	switch os.Args[1] {
	case "init":
		fs := flag.NewFlagSet("init", flag.ContinueOnError)
		path := fs.String("state-dir", "", "private bridge state")
		if err := fs.Parse(os.Args[2:]); err != nil {
			return err
		}
		if *path == "" || !filepath.IsAbs(*path) {
			return errors.New("absolute state directory required")
		}
		transport, err := serverFactory(*path, true)
		if err != nil {
			return err
		}
		args := pt.Args{}
		args.Add("iat-mode", strconv.Itoa(timingMode))
		sf, err := transport.ServerFactory(*path, &args)
		if err != nil {
			return err
		}
		cert, _ := sf.Args().Get("cert")
		return json.NewEncoder(os.Stdout).Encode(map[string]interface{}{"cert": cert, "iat_mode": timingMode})
	case "run":
		fs := flag.NewFlagSet("run", flag.ContinueOnError)
		path := fs.String("config", "", "root-owned runtime configuration")
		if err := fs.Parse(os.Args[2:]); err != nil {
			return err
		}
		c, err := loadConfig(*path)
		if err != nil {
			return err
		}
		return serve(c)
	default:
		return errors.New("unsupported command")
	}
}
func main() {
	if run() != nil {
		fmt.Fprintln(os.Stderr, "transport operation failed; inspect local configuration and identity state")
		os.Exit(1)
	}
}
