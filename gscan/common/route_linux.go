//go:build linux

package common

import (
	"log"
	"net"
	"runtime"
	"syscall"
)

func GetGateways() []net.IP {
	ret := []net.IP{}
	if runtime.GOOS == `linux` {
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
	} else if runtime.GOOS == `windows` {

	} else if runtime.GOOS == `darwin` {

	}

	return ret
}
