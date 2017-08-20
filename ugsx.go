package killswitch

import (
	"errors"
	"net"
	"syscall"

	"golang.org/x/net/route"
)

const (
	// UGSH man netstat
	UGSH = syscall.RTF_UP | syscall.RTF_GATEWAY | syscall.RTF_STATIC | syscall.RTF_HOST
	// UGSc man netstat
	UGSc = syscall.RTF_UP | syscall.RTF_GATEWAY | syscall.RTF_STATIC | syscall.RTF_PRCLONING
)

func privateIP(ip string) (bool, error) {
	var err error
	private := false
	IP := net.ParseIP(ip)
	if IP == nil {
		err = errors.New("Invalid IP")
	} else {
		_, private24BitBlock, _ := net.ParseCIDR("10.0.0.0/8")
		_, private20BitBlock, _ := net.ParseCIDR("172.16.0.0/12")
		_, private16BitBlock, _ := net.ParseCIDR("192.168.0.0/16")
		private = private24BitBlock.Contains(IP) || private20BitBlock.Contains(IP) || private16BitBlock.Contains(IP)
	}
	return private, err
}

// UGSX find IP of the vpn by matching existing route flags, man netstat
func UGSX() (net.IP, error) {
	rib, err := route.FetchRIB(syscall.AF_UNSPEC, route.RIBTypeRoute, 0)
	if err != nil {
		return nil, err
	}
	msgs, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return nil, err
	}
	var ip net.IP
	for _, msg := range msgs {
		m := msg.(*route.RouteMessage)
		if m.Flags == UGSH || m.Flags == UGSc {
			switch a := m.Addrs[syscall.AF_UNSPEC].(type) {
			case *route.Inet4Addr:
				ip = net.IPv4(a.IP[0], a.IP[1], a.IP[2], a.IP[3])
			case *route.Inet6Addr:
				ip = make(net.IP, net.IPv6len)
				copy(ip, a.IP[:])
			}
			if ok, err := privateIP(ip.String()); err != nil {
				continue
			} else if !ok {
				switch ip.String() {
				case "0.0.0.0":
					continue
				case "128.0.0.0":
					continue
				default:
					return ip, nil
				}
			}
		}
	}
	return ip, nil
}
