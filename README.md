# killswitch

Fail-closed VPN kill switch for macOS. It supports dynamic Network Extension
packet tunnels such as AdGuard VPN as well as WireGuard and Tailscale.

## How it works

macOS Network Extension VPNs do not necessarily expose their remote server as
a routing-table gateway. Killswitch therefore detects the two parts of the VPN
path independently:

- the active `utunN` is selected from its tunnel addresses and routed prefixes;
- the physical path comes from the default route (for example, `en0`);
- the outer endpoint, protocol, and port come from sockets owned by a known VPN
  provider process (for example, `AdGuard VPN` using UDP/443).

The generated policy permits loopback, DHCP, the selected VPN endpoint on the
physical interface, and traffic on only the selected tunnel. Its final rule
blocks all other outbound IPv4 and IPv6 traffic. If detection is uncertain, no
tunnel allow rule is emitted.

Rules are loaded only into the `killswitch` PF anchor. The program never runs
`pfctl -Fa` or flushes another anchor. On first use only, if `/etc/pf.conf` has
no `anchor "killswitch"` attachment point, killswitch validates and adds that
single line, saves `/etc/pf.conf.killswitch.backup`, and reloads `/etc/pf.conf`
without a flush flag. If the line exists after another filter anchor, it is
moved before those anchors so their `quick` rules cannot bypass the kill
switch. Allowed packets are tagged and continue through later system anchors;
only disallowed direct traffic terminates evaluation with `block quick`.

When enabled, a small root monitor checks the route, tunnel and provider
sockets every two seconds. A reconnect from `utun4` to `utun5` reloads only
the killswitch anchor. The endpoint detected at enable time is pinned: when
the tunnel disappears its allow rule is removed, but that endpoint remains
allowed so the provider can reconnect to the same server. A different server
endpoint is not learned from direct sockets while the kill switch is active;
disable, connect to the new server, then enable again.

For AdGuard VPN, `--reconnect` additionally permits up to eight temporary
TCP/UDP port 443 destinations currently opened by the AdGuard process. The set
is replaced on every monitor pass and never accumulated. This lets AdGuard run
its bootstrap/connectivity checks and reconnect automatically, at the cost of
narrow direct exceptions to those observed destinations.

## Usage

Show the detected VPN path:

    killswitch -vv

Preview the exact PF anchor rules:

    killswitch --print -vv

Enable the kill switch and monitor:

    sudo killswitch -e -v

Enable automatic AdGuard reconnect support:

    sudo killswitch -e --reconnect -v

Show anchor counters or disable it:

    sudo killswitch --status
    sudo killswitch -d -v

`--ipv4 <IP>` remains available for compatibility, but it is not required for
AdGuard VPN when its provider socket is visible. A manual endpoint permits TCP
and UDP to that IP because the legacy flag has no protocol or port information.

### Options

| Flag | Description |
|------|-------------|
| `-e`, `--enable` | Enable the anchor and dynamic monitor |
| `-d`, `--disable` | Stop the monitor and flush only this anchor |
| `-s`, `--status` | Show rules and packet counters for this anchor |
| `-p`, `--print` | Print rules without applying them |
| `--local` | Permit traffic within the physical interface's local network |
| `--reconnect` | Temporarily permit bounded AdGuard bootstrap sockets on port 443 |
| `--leak` | Explicitly permit direct DNS and ICMP (reduces leak protection) |
| `--ipv4 <IP>` | Legacy manual public IPv4 endpoint override |
| `-v`, `-vv` | Verbose / debug output |

## macOS verification

PF's main `-sr` view shows the anchor call, not the nested rules. Inspect the
anchor and its counters explicitly:

    sudo pfctl -a killswitch -vvsr
    sudo pfctl -ss

Observe the inner and outer paths in separate terminals:

    sudo tcpdump -ni en0
    sudo tcpdump -ni utun4

Test both address families. With the VPN connected, IPv4 must show the VPN
address; IPv6 must show a VPN address or time out. With the VPN disconnected
while killswitch remains enabled, both commands must time out:

    curl -4 --max-time 10 https://api.ipify.org
    curl -6 --max-time 10 https://api64.ipify.org

Apple documents PF as a legacy, unsupported API for third-party products. This
project therefore validates the generated rules before loading them and keeps
all normal updates scoped to its anchor, but final packet-path verification is
still required on each supported macOS release.

## Build and test

    just test
    cargo build --release --locked

The ignored real-PF parser test is non-mutating but requires root:

    sudo env CARGO_TARGET_DIR=/private/tmp/killswitch-root-tests \
      cargo test test_real_pf_parser_integration -- --ignored
