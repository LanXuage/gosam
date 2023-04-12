//go:build linux

package common

import (
	"net"
	"syscall"

	"go.uber.org/zap"
)

func GetGateways() []net.IP {
	ret := []net.IP{}
	netlinks, err := syscall.NetlinkRIB(syscall.RTM_GETROUTE, syscall.AF_INET)
	if err != nil {
		logger.Error("NetlinkRIB failed", zap.Error(err))
	}
	nmsg, err := syscall.ParseNetlinkMessage(netlinks)
	if err != nil {
		logger.Error("ParseNetlinkMsg failed", zap.Any("netlinks", netlinks), zap.Error(err))
	}
	for _, m := range nmsg {
		if m.Header.Type == syscall.RTM_NEWROUTE {
			attrs, err := syscall.ParseNetlinkRouteAttr(&m)
			if err != nil {
				logger.Error("ParseNetlinkRouteAttr failed", zap.Any("nmsg", m), zap.Error(err))
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
