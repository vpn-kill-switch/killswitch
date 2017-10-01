package killswitch_test

import (
	"testing"

	"github.com/vpn-kill-switch/killswitch"
)

const succeeded = "\u2713"
const failed = "\u2717"

func TestKillSwitch(t *testing.T) {
	tt := []struct {
		peerIp     string
		expectedIp string
	}{
		{
			peerIp:     "127.0.0.1",
			expectedIp: "127.0.0.1",
		},
		{
			peerIp:     "1.2.3.4",
			expectedIp: "1.2.3.4",
		},
		{
			peerIp:     "",
			expectedIp: "0.0.0.0",
		},
	}

	for i, tst := range tt {
		t.Logf("\tTest %d: \t%s", i, tst.peerIp)
		network, _ := killswitch.New(tst.peerIp)

		if network.PeerIP != tst.expectedIp {
			t.Fatalf("\t%s\t Should have correct peer IP:  exp[%s] got[%s] ", failed, tst.peerIp, network.PeerIP)
		}
		t.Logf("\t%s\t Should have correct peer IP", succeeded)

		if len(network.P2PInterfaces) != 0 {
			t.Fatalf("\t%s\t Should have correct P2PInterfaces length:  exp[%d] got[%d] ", failed, 0, len(network.P2PInterfaces))
		}
		t.Logf("\t%s\t Should have correct P2PInterfaces ", succeeded)

		if len(network.UpInterfaces) != 0 {
			t.Fatalf("\t%s\t Should have correct UpInterfaces length:  exp[%d] got[%d] ", failed, 0, len(network.UpInterfaces))
		}
		t.Logf("\t%s\t Should have correct UpInterfaces ", succeeded)
	}
}
