package killswitch

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/miekg/dns"
)

// WhoamiDNS return public ip by quering DNS server
func WhoamiDNS() (string, error) {
	var record *dns.TXT

	target := "o-o.myaddr.l.google.com"
	server := "ns1.google.com"

	c := dns.Client{}
	m := dns.Msg{}

	m.SetQuestion(target+".", dns.TypeTXT)
	r, _, err := c.Exchange(&m, server+":53")

	if err != nil {
		return "", err
	}

	if len(r.Answer) == 0 {
		return "", fmt.Errorf("could not found public IP")
	}

	for _, ans := range r.Answer {
		record = ans.(*dns.TXT)
	}

	return strings.TrimSpace(record.Txt[0]), nil
}

// WhoamiWWW return IP by quering http server
func WhoamiWWW() (string, error) {
	client := &http.Client{}
	// Create request
	req, err := http.NewRequest("GET", "http://checkip.amazonaws.com/", nil)
	// Fetch Request
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	// Read Response Body
	respBody, _ := ioutil.ReadAll(resp.Body)
	return strings.TrimSpace(string(respBody)), nil
}
