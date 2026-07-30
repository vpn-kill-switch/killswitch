# Implementation notes

## macOS Network Extension model

`NEPacketTunnelProvider` associates routes and addresses with a virtual
interface, then reads and writes packets through `NEPacketTunnelFlow`. The
provider's encapsulating socket uses the physical network path and is not
required to appear as a conventional VPN gateway route.

On the AdGuard VPN system used during development:

- `route -n get default` remains `en0` via the LAN gateway;
- `utun4` owns `172.16.209.2`, `fd00::2`, and the broad VPN routes;
- `utun0` through `utun3` have only link-local/service routes and are unrelated;
- `scutil --nc list` does not expose the active AdGuard packet tunnel;
- `lsof -F pcPnT` exposes `AdGuard VPN` transport sockets from the `en0`
  address to the current public server.

The detector therefore does not interpret the `utun` peer `127.1.1.1`, the
tunnel address, the public exit IP, or an arbitrary static route as the outer
VPN endpoint.

Relevant platform documentation:

- [NEPacketTunnelProvider](https://developer.apple.com/documentation/networkextension/nepackettunnelprovider)
- [TN3120: Expected use cases for Network Extension packet tunnel providers](https://developer.apple.com/documentation/technotes/tn3120-expected-use-cases-for-network-extension-packet-tunnel-providers)
- [TN3165: Packet Filter is not API](https://developer.apple.com/documentation/technotes/tn3165-packet-filter-is-not-api)

## Detection

`network::VpnInfo` carries the selected tunnel, tunnel addresses, physical
interface and addresses, routes, VPN type, service name, and one or more outer
endpoints with transport and port.

The active `utunN` is scored from broad routes whose gateway and output
interface are that `utun`, plus a configured tunnel IPv4 address. A link-local
`utun` alone is not considered an active VPN. Endpoint sources are:

1. known VPN-provider sockets bound to a physical interface address;
2. `wg show all endpoints`;
3. connected `scutil --nc show` `RemoteAddress` values.

AdGuard also creates one-off physical-interface sockets for connectivity and
DNS probes. Its endpoint selector therefore accepts only a unique remote that
is repeated across multiple provider sockets; an ambiguous observation fails
closed.

An unknown endpoint never produces a physical-interface Internet allow rule.

## PF lifecycle

The main configuration contains only an attachment point:

    anchor "killswitch"

It is placed before other filter-anchor calls. Allowed packets receive the
unique `KILLSWITCH_ALLOWED` tag and continue into later system anchors, while
the inverse-tagged direct block is `quick`. This prevents an earlier system
`pass quick` from bypassing the kill switch without making allowed VPN packets
bypass later system filtering.

Normal enable, reload, and disable operations target only that anchor:

    pfctl -a killswitch -f /var/run/killswitch.pf.conf
    pfctl -a killswitch -F rules

PF is acquired and released with `-E`/`-X` reference tokens. No code path uses
`-Fa`, `-F all`, `-F states`, or disables PF globally.

Because PF evaluates an established state before evaluating new filter rules,
initial enable and path changes terminate only states sourced from the current
physical local IPv4/IPv6 addresses (`pfctl -k <address>`). The operation is
needed to prevent a pre-existing direct connection from bypassing a newly
loaded anchor; it does not flush the state table.

## Dynamic fail-closed behavior

The monitor runs every two seconds. It replaces the tunnel allow rule after a
route change and removes it when the VPN disappears. Endpoint exceptions are
detected and pinned when the kill switch is enabled, then persisted in the
root-only runtime monitor configuration. Later direct sockets never expand
that allowlist. This permits reconnection to the same endpoint; switching to a
different server requires disabling and enabling the kill switch around the
server change.

The opt-in `--reconnect` mode also emits separately labeled
`killswitch-bootstrap` rules for TCP/UDP port 443 destinations currently
opened by the exact `AdGuard VPN` process. The monitor replaces this temporary
set every two seconds, excludes the pinned transport endpoint, and caps it at
eight destinations. These narrow direct exceptions let AdGuard complete its
connectivity checks and discover a new transport endpoint without adding a
wildcard Internet exception.

The monitor keeps no wildcard physical Internet exception. A missing tunnel,
endpoint, physical path, malformed route table, or transient detection failure
therefore results in fewer allow rules, not more.

## PF packet-path diagnosis

Generated labels make counter inspection unambiguous:

    sudo pfctl -a killswitch -vvsr
    sudo pfctl -ss

Capture both layers while generating traffic:

    sudo tcpdump -ni en0
    sudo tcpdump -ni utun4

The `killswitch-vpn` counter should increase for application packets on the
tunnel, `killswitch-endpoint` for encapsulated packets on `en0`, and
`killswitch-direct-block` for attempted leaks. `pfctl -sr` intentionally shows
only the anchor call; use `-a killswitch` (or recursive `-a '*'`) for its rules.
