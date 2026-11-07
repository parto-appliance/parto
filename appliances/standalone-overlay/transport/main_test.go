package main

import (
	"encoding/json"
	pt "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/goptlib"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/transports/obfs4"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestPersistentIdentityAndPrivateState(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	tr, err := serverFactory(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	args := pt.Args{}
	args.Add("iat-mode", strconv.Itoa(timingMode))
	first, err := tr.ServerFactory(dir, &args)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := first.Args().Get("cert")
	if mode, _ := first.Args().Get("iat-mode"); mode != "0" {
		t.Fatalf("expected timing mode 0, got %q", mode)
	}
	if !stateExists(dir) {
		t.Fatal("state must be private and persistent")
	}
	second, err := tr.ServerFactory(dir, &args)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := second.Args().Get("cert")
	if again != cert {
		t.Fatal("identity changed")
	}
	os.Remove(filepath.Join(dir, "obfs4_state.json"))
	if _, err := serverFactory(dir, false); err == nil {
		t.Fatal("run must not silently regenerate identity")
	}
}
func TestUpstreamObfs4StreamAndWrongDescriptor(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	tr := &obfs4.Transport{}
	args := pt.Args{}
	args.Add("iat-mode", strconv.Itoa(timingMode))
	sf, err := tr.ServerFactory(dir, &args)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan error, 1)
	go func() {
		conn, e := listener.Accept()
		if e != nil {
			done <- e
			return
		}
		defer conn.Close()
		wrapped, e := sf.WrapConn(conn)
		if e != nil {
			done <- e
			return
		}
		defer wrapped.Close()
		data := make([]byte, 5)
		_, e = io.ReadFull(wrapped, data)
		if e == nil {
			_, e = wrapped.Write(data)
		}
		done <- e
	}()
	cf, _ := tr.ClientFactory("")
	parsed, err := cf.ParseArgs(sf.Args())
	if err != nil {
		t.Fatal(err)
	}
	c, err := cf.Dial("tcp4", listener.Addr().String(), net.Dial, parsed)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	c.Write([]byte("hello"))
	out := make([]byte, 5)
	if _, err = io.ReadFull(c, out); err != nil || string(out) != "hello" {
		t.Fatal("upstream stream interoperability failed", err)
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	bad := pt.Args{}
	bad.Add("cert", "not-a-bridge-descriptor")
	bad.Add("iat-mode", strconv.Itoa(timingMode))
	if _, err = cf.ParseArgs(&bad); err == nil {
		t.Fatal("invalid descriptor accepted")
	}
}
func TestConfigRejectsExposureAndUnknownFields(t *testing.T) {
	c := config{Role: "spoke", Listen: "127.0.0.1:3443", Target: "198.51.100.10:443", Source: "192.0.2.2", Interface: "eth0", Cert: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	p := filepath.Join(t.TempDir(), "config.json")
	write := func() { b, _ := json.Marshal(c); os.WriteFile(p, b, 0600) }
	write()
	if _, err := loadConfig(p); err != nil {
		t.Fatal(err)
	}
	c.Listen = "0.0.0.0:3443"
	write()
	if _, err := loadConfig(p); err == nil {
		t.Fatal("public client proxy accepted")
	}
	os.WriteFile(p, []byte(`{"unknown":true}`), 0600)
	if _, err := loadConfig(p); err == nil {
		t.Fatal("unknown fields accepted")
	}
}
