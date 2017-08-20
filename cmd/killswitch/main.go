package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"strings"

	"github.com/vpn-kill-switch/killswitch"
)

// PadRight add spaces for aligning the output
func PadRight(str, pad string, length int) string {
	for {
		str += pad
		if len(str) > length {
			return str[0:length]
		}
	}
}

func exit1(err error) {
	fmt.Println(err)
	os.Exit(1)
}

var version string

func main() {

	var (
		ip = flag.String("ip", "", "VPN peer `IPv4`, killswitch tries to find this automatically")
		d  = flag.Bool("d", false, "`Disable` load /etc/pf.conf rules")
		e  = flag.Bool("e", false, "`Enable` load the pf rules")
		p  = flag.Bool("p", false, "`Print` the pf rules")
		v  = flag.Bool("v", false, fmt.Sprintf("Print version: %s", version))
	)

	flag.Parse()

	if *v {
		fmt.Printf("%s\n", version)
		os.Exit(0)
	}

	if *d {
		exec.Command("pfctl", "-e").CombinedOutput()
		fmt.Printf("# %s\n", strings.Repeat("-", 62))
		fmt.Println("# Loading /etc/pf.conf rules")
		fmt.Printf("# %s\n", strings.Repeat("-", 62))
		out, _ := exec.Command("pfctl",
			"-Fa",
			"-f",
			"/etc/pf.conf").CombinedOutput()
		fmt.Printf("%s\n", out)
		out, _ = exec.Command("pfctl", "-sr").CombinedOutput()
		fmt.Printf("%s\n", out)
		return
	}

	ks, err := killswitch.New(*ip)
	if err != nil {
		exit1(err)
	}

	err = ks.GetActive()
	if err != nil {
		exit1(err)
	}

	if len(ks.UpInterfaces) == 0 {
		exit1(fmt.Errorf("No active interfaces found, verify network settings, use (\"%s -h\") for help.\n", os.Args[0]))
	}

	fmt.Println("Interface  MAC address         IP")
	for k, v := range ks.UpInterfaces {
		fmt.Printf("%s %s   %s\n", PadRight(k, " ", 10), v[0], v[1])
	}
	for k, v := range ks.P2PInterfaces {
		fmt.Printf("%s %s   %s\n", PadRight(k, " ", 10), PadRight(v[0], " ", 17), v[1])
	}
	// check for DNS leaks
	if ipDNS, err := killswitch.WhoamiDNS(); err == nil {
		if ipWWW, err := killswitch.WhoamiWWW(); err == nil {
			if ipDNS != ipWWW {
				fmt.Printf("\n%s:\n", killswitch.Red("DNS leaking"))
				fmt.Printf("Public IP address (DNS): %s\n", killswitch.Red(ipDNS))
				fmt.Printf("Public IP address (WWW): %s\n", killswitch.Red(ipWWW))
			} else {
				fmt.Printf("\nPublic IP address: %s\n", killswitch.Red(ipDNS))
			}
		}
	}

	// add some space
	println()

	if len(ks.P2PInterfaces) == 0 {
		exit1(fmt.Errorf("No VPN interface found, verify VPN is connected"))
	}

	fmt.Printf("PEER IP address:   %s\n", killswitch.Yellow(ks.PeerIP))

	if *ip != "" {
		if ipv4 := net.ParseIP(*ip); ipv4.To4() == nil {
			exit1(fmt.Errorf("%s is not a valid IPv4 address, use (\"%s -h\") for help.\n", *ip, os.Args[0]))
		}
	}

	ks.CreatePF()

	fmt.Printf("\n%s: %s\n", "To enable the kill switch run", killswitch.Green("sudo killswitch -e"))
	fmt.Printf("%s: %s\n\n", "To disable", killswitch.Yellow("sudo killswitch -d"))

	if *p {
		fmt.Printf("PF rules to be loaded:\n")
		fmt.Println(ks.PFRules.String())
	}

	if err = ioutil.WriteFile("/tmp/killswitch.pf.conf",
		ks.PFRules.Bytes(),
		0644,
	); err != nil {
		exit1(err)
	}

	if *e {
		fmt.Printf("# %s\n", strings.Repeat("-", 62))
		fmt.Println("# Loading rules")
		fmt.Printf("# %s\n", strings.Repeat("-", 62))
		out, _ := exec.Command("pfctl", "-e").CombinedOutput()
		fmt.Printf("%s\n", out)
		out, _ = exec.Command("pfctl",
			"-Fa",
			"-f",
			"/tmp/killswitch.pf.conf").CombinedOutput()
		fmt.Printf("%s\n", out)
		out, _ = exec.Command("pfctl", "-sr").CombinedOutput()
		fmt.Printf("%s\n", out)
	}
}
