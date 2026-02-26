# killswitch

VPN kill switch for macOS. Blocks all outgoing traffic when the VPN connection
drops, preventing your real IP from leaking.

## How it works

When enabled, killswitch loads [pf](https://docs.freebsd.org/en/books/handbook/firewalls/#firewalls-pf) firewall
rules that only allow traffic through the VPN tunnel. If the VPN disconnects,
the tunnel interface disappears but the firewall rules remain — blocking all
internet traffic until the VPN reconnects or the kill switch is disabled.

Rules are written to `/tmp/killswitch.pf.conf` and loaded with `pfctl`.
The system default `/etc/pf.conf` is never modified.

## Usage

Show network interfaces, public IP, and detected VPN peer:

    $ killswitch

Enable the kill switch (requires root):

    $ sudo killswitch -e

Disable and restore default firewall rules:

    $ sudo killswitch -d

Print the firewall rules without applying them:

    $ killswitch --print

### Options

| Flag | Description |
|------|-------------|
| `--leak` | Allow ICMP (ping) and DNS requests outside the VPN |
| `--local` | Allow local network traffic |
| `--ipv4 <IP>` | Manually specify the VPN peer IP (auto-detected if omitted) |
| `-v`, `-vv` | Verbose / debug output |

### Examples

Enable with DNS leak and local network access:

    $ sudo killswitch -e --leak --local

Specify the VPN peer IP manually:

    $ sudo killswitch -e --ipv4 203.0.113.1

Preview rules in debug mode:

    $ killswitch --print --leak -vv

## VPN detection

The VPN gateway IP is auto-detected using multiple methods (in order):

1. **sysctl** — reads the kernel routing table directly
2. **netstat** — parses routes with `UGSH`/`UGSc` flags
3. **scutil** — queries macOS Network Extension services (works with WireGuard, ProtonVPN, etc.)
4. **ifconfig** — extracts peer addresses from tunnel interfaces

If auto-detection fails, use `--ipv4` to specify the VPN peer IP manually.

## Build from source

Requires [Rust](https://www.rust-lang.org/tools/install):

    $ cargo build --release
    $ sudo cp target/release/killswitch /usr/local/bin/

### Development

    $ just test       # format check + clippy + tests
    $ just fmt        # check formatting
    $ just clippy     # lint all targets
