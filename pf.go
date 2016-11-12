package killswitch

import (
	"bytes"
	"fmt"
	"strings"
	"time"
)

// CreatePF creates a pf.conf
func (n *Network) CreatePF() {
	var antispoof, pass bytes.Buffer
	n.PFRules.WriteString(fmt.Sprintf("# %s\n", strings.Repeat("-", 62)))
	n.PFRules.WriteString(fmt.Sprintf("# %s\n", time.Now().Format(time.RFC1123Z)))
	n.PFRules.WriteString("# sudo pfctl -Fa -f ~/.killswitch.pf.conf -e\n")
	n.PFRules.WriteString(fmt.Sprintf("# %s\n", strings.Repeat("-", 62)))

	// create var for interfaces
	for k := range n.UpInterfaces {
		n.PFRules.WriteString(fmt.Sprintf("int_%s = %q\n", k, k))
		antispoof.WriteString(fmt.Sprintf("antispoof for $int_%s inet\n", k))
		pass.WriteString(fmt.Sprintf("pass out on $int_%s inet proto icmp all icmp-type 8 code 0\n", k))
		pass.WriteString(fmt.Sprintf("pass out on $int_%s proto {tcp, udp} from any to $vpn_ip\n", k))
	}
	// create var for vpn
	for k := range n.P2PInterfaces {
		n.PFRules.WriteString(fmt.Sprintf("vpn_%s = %q\n", k, k))
		antispoof.WriteString(fmt.Sprintf("antispoof for $vpn_%s inet\n", k))
		pass.WriteString(fmt.Sprintf("pass out on $vpn_%s all\n", k))
	}
	// add vpn peer IP
	n.PFRules.WriteString(fmt.Sprintf("vpn_ip = %q\n", n.PeerIP))
	n.PFRules.WriteString("set block-policy drop\n")
	n.PFRules.WriteString("set ruleset-optimization basic\n")
	n.PFRules.WriteString("set skip on lo0\n")
	n.PFRules.WriteString("block out all\n")
	n.PFRules.WriteString("block in all\n")
	n.PFRules.WriteString(antispoof.String())
	n.PFRules.WriteString(pass.String())
}
