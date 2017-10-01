package killswitch

import (
	"testing"
)

const succeeded = "\u2713"
const failed = "\u2717"

func TestUgsx(t *testing.T) {
	tt := []struct {
		peerIP    string
		isPrivate bool
	}{
		{
			peerIP:    "127.0.0.1",
			isPrivate: false,
		},
		{
			peerIP:    "10.0.0.1",
			isPrivate: true,
		},
		{
			peerIP:    "172.16.0.0",
			isPrivate: true,
		},
		{
			peerIP:    "192.168.0.0",
			isPrivate: true,
		},
		{
			peerIP:    "invalid",
			isPrivate: false,
		},
	}

	for i, tst := range tt {
		t.Logf("\tTest %d: \t%s", i, tst.peerIP)
		isPrivate, _ := privateIP(tst.peerIP)

		if isPrivate != tst.isPrivate {
			t.Fatalf("\t%s\t Should be private [%t] : got[%t] ", failed, tst.isPrivate, isPrivate)
		}
		t.Logf("\t%s\t Should be private [%t] ", succeeded, tst.isPrivate)
	}
}
