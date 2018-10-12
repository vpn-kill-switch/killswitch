package killswitch

import (
	"bytes"
	"fmt"
	"strings"
	"time"
)

// CreatePF creates a pf.conf
func (n *Network) CreatePF(leak, local, airdrop bool) {
	var pass bytes.Buffer
	n.PFRules.WriteString(fmt.Sprintf("# %s\n", strings.Repeat("-", 62)))
	n.PFRules.WriteString(fmt.Sprintf("# %s\n", time.Now().Format(time.RFC1123Z)))
	n.PFRules.WriteString("# sudo pfctl -Fa -f /tmp/killswitch.pf.conf -e\n")
	n.PFRules.WriteString(fmt.Sprintf("# %s\n", strings.Repeat("-", 62)))

	// create var for interfaces
	for k := range n.UpInterfaces {
		n.PFRules.WriteString(fmt.Sprintf("int_%s = %q\n", k, k))
		pass.WriteString(fmt.Sprintf("pass on $int_%s proto {tcp,udp} from any port 67:68 to any port 67:68 keep state\n", k))
		if leak {
			pass.WriteString(fmt.Sprintf("pass on $int_%s inet proto icmp all icmp-type 8 code 0\n", k))
		}
		if local {
			pass.WriteString(fmt.Sprintf("pass from $int_%s:network to $int_%s:network\n", k, k))
		}
		pass.WriteString(fmt.Sprintf("pass on $int_%s proto {tcp, udp} from any to $vpn_ip\n", k))
	}
	// create var for vpn
	for k := range n.P2PInterfaces {
		n.PFRules.WriteString(fmt.Sprintf("vpn_%s = %q\n", k, k))
		pass.WriteString(fmt.Sprintf("pass on $vpn_%s all\n", k))
	}
	// add vpn peer IP
	n.PFRules.WriteString(fmt.Sprintf("vpn_ip = %q\n", n.PeerIP))
	n.PFRules.WriteString("set block-policy drop\n")
	n.PFRules.WriteString("set ruleset-optimization basic\n")
	n.PFRules.WriteString("set skip on lo0\n")
	n.PFRules.WriteString("block all\n")
	if leak {
		n.PFRules.WriteString("pass quick proto {tcp, udp} from any to any port 53 keep state\n")
	}
	n.PFRules.WriteString("pass from any to 255.255.255.255 keep state\n")
	n.PFRules.WriteString("pass from 255.255.255.255 to any keep state\n")
	n.PFRules.WriteString("pass proto udp from any to 224.0.0.0/4 keep state\n")
	n.PFRules.WriteString("pass proto udp from 224.0.0.0/4 to any keep state\n")
	if airdrop {
		n.PFRules.WriteString("pass on awdl0 all\n")
	}
	n.PFRules.WriteString(pass.String())
}
