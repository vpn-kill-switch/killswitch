package killswitch

import "github.com/miekg/dns"

// Whoami return public ip
func Whoami() string {
	var record *dns.TXT

	target := "o-o.myaddr.l.google.com"
	server := "ns1.google.com"

	c := dns.Client{}
	m := dns.Msg{}

	m.SetQuestion(target+".", dns.TypeTXT)
	r, _, err := c.Exchange(&m, server+":53")

	if err != nil {
		return "Could not found public IP"
	}

	if len(r.Answer) == 0 {
		return "Could not found public IP"
	}

	for _, ans := range r.Answer {
		record = ans.(*dns.TXT)
	}

	return record.Txt[0]
}
