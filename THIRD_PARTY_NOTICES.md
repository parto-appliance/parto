# Third-party software

The MIT license covers this project's own source. It does not relicense the
Debian operating system, Linux kernel, FRRouting, strongSwan, stunnel, OpenVPN,
dnsmasq, Qt, Python, boot loaders or other distribution packages in the image.
Their copyright and license notices remain in `/usr/share/doc/<package>/copyright`.

The image build records package names and versions. Before distributing a binary
release, retain the corresponding source packages and license notices required by
those licenses alongside the release materials. Debian publishes source packages
through its source repositories and snapshot archive:

- https://www.debian.org/legal/licenses/
- https://sources.debian.org/
- https://snapshot.debian.org/

VMware, Oracle VirtualBox and Starlink are third-party products. Vendor screenshots
and names in the deployment guides are attributed to their original sources;
they do not imply endorsement. Live screenshots of this appliance are examples
from the documented test environment, with no user credentials or private keys.

## Transport dependencies

The appliance includes third-party code from the Tor Project’s Lyrebird project.
Upstream source and original
BSD notices are preserved under `appliances/standalone-overlay/transport/vendor/`.
Go LICENSE/PATENTS and the pinned upstream/toolchain record are in the transport
directory. Corresponding notices are installed in `/usr/share/doc/parto-transport/`.
The project's MIT license does not replace these third-party licenses.

Lyrebird commit: `362a60bb4e3fa434130ef81a9990d83d6d8eaea5`.
The source distribution includes vendored dependencies/checksums for offline
compilation.
