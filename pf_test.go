package killswitch_test

import (
	"strings"
	"testing"

	"github.com/vpn-kill-switch/killswitch"
)

func TestPf(t *testing.T) {
	tt := []struct {
		peerIp            string
		expectedVpnString string
	}{
		{
			peerIp:            "127.0.0.1",
			expectedVpnString: "vpn_ip = \"127.0.0.1\"",
		},
		{
			peerIp:            "1.2.3.4",
			expectedVpnString: "vpn_ip = \"1.2.3.4\"",
		},
		{
			peerIp:            "",
			expectedVpnString: "vpn_ip = \"0.0.0.0\"",
		},
	}

	for i, tst := range tt {
		t.Logf("\tTest %d: \t%s", i, tst.peerIp)
		network, _ := killswitch.New(tst.peerIp)
		network.CreatePF()

		configFileContents := network.PFRules.String()

		if !strings.Contains(configFileContents, tst.expectedVpnString) {
			t.Fatalf("\t%s\t Should contain vpn string:  exp[%s] got[%s] ", failed, tst.expectedVpnString, configFileContents)
		}
		t.Logf("\t%s\t Should contain vpn string ", succeeded)
	}
}
