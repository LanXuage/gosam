package common

import (
	"log"
	"net"
	"strings"
	"syscall"
)

func GetOuiPrefix(mac net.HardwareAddr) (string, string) {
	ret1 := strings.ToUpper(strings.Replace(mac.String()[:8], ":", "", -1))
	ret2 := strings.ToUpper(strings.Replace(mac.String()[:13], ":", "", -1))
	return ret1, ret2
}

func GetGateways() []net.IP {
	ret := []net.IP{}
	netlinks, err := syscall.NetlinkRIB(syscall.RTM_GETROUTE, syscall.AF_INET)
	if err != nil {
		log.Fatal(err)
	}
	nmsg, err := syscall.ParseNetlinkMessage(netlinks)
	if err != nil {
		log.Fatal(err)
	}
	for _, m := range nmsg {
		if m.Header.Type == syscall.RTM_NEWROUTE {
			attrs, err := syscall.ParseNetlinkRouteAttr(&m)
			if err != nil {
				log.Fatal(err)
			}
			for _, attr := range attrs {
				if attr.Attr.Type == syscall.RTA_GATEWAY {
					ret = append(ret, attr.Value)
				}
			}
		}
	}
	return ret
}

func IP2Uint32(ip net.IP) uint32 {
	var sum uint32
	sum += uint32(ip[0]) << 24
	sum += uint32(ip[1]) << 16
	sum += uint32(ip[2]) << 8
	return sum + uint32(ip[3])
}

func IPMask2Uint32(mask net.IPMask) uint32 {
	return IP2Uint32(net.IP(mask))
}

func Uint322IP(ipUint32 uint32) net.IP {
	return net.IPv4(byte((ipUint32>>24)&0xff), byte((ipUint32>>16)&0xff), byte((ipUint32>>8)&0xff), byte(ipUint32&0xff))
}