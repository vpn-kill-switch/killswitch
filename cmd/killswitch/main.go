package main

import (
	"flag"
	"fmt"
	"net"
	"os"

	"github.com/nbari/killswitch"
)

func exit1(err error) {
	fmt.Println(err)
	os.Exit(1)
}

var version string

func main() {

	var (
		ip = flag.String("ip", "", "VPN peer `IPv4`")
		v  = flag.Bool("v", false, fmt.Sprintf("Print version: %s", version))
	)

	flag.Parse()

	if *v {
		fmt.Printf("%s\n", version)
		os.Exit(0)
	}

	if *ip == "" {
		exit1(fmt.Errorf("Please enter the VPN peer IP, use (\"%s -h\" for help.\n", os.Args[0]))
	} else if ipv4 := net.ParseIP(*ip); ipv4.To4() == nil {
		exit1(fmt.Errorf("%s is not a valid IPv4 address, use (\"%s -h\") for help.\n", *ip, os.Args[0]))
	}

	ks, err := killswitch.New(*ip)
	if err != nil {
		exit1(err)
	}

	err = ks.GetActive()
	if err != nil {
		exit1(err)
	}

	ks.CreatePF()

	fmt.Println(ks.PFRules.String())
}
