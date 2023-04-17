package common

import (
	"net"
	"net/netip"

	"github.com/google/gopacket/pcap"
	"go.uber.org/zap"
)

type GSInterface struct {
	Name    string           // 接口名称
	Gateway netip.Addr       // 接口网关IP
	Mask    netip.Prefix     // 接口掩码
	HWAddr  net.HardwareAddr // 接口物理地址
	IP      netip.Addr       // 接口IP
	Handle  *pcap.Handle     // 接口pcap句柄
}

var localhost, _ = netip.ParseAddr("127.0.0.1")

func getActiveInterfaces() *[]GSInterface {
	gsInterfaces := make([]GSInterface, 0)
	gateways := GetGateways()
	devs, err := pcap.FindAllDevs()
	if err != nil {
		logger.Error("FindAllDevs failed", zap.Error(err))
	}
	ifs, err := net.Interfaces()
	if err != nil {
		logger.Error("Net Interfaces failed", zap.Error(err))
	}
	for _, gateway := range gateways {
		for _, dev := range devs {
			if dev.Addresses == nil {
				continue
			}
			for _, addr := range dev.Addresses {
				if addr.IP == nil {
					continue
				}
				ones, _ := addr.Netmask.Size()
				ip, ok := netip.AddrFromSlice(addr.IP)
				if !ok || ip == localhost {
					continue
				}
				ipPrefix, err := ip.Prefix(ones)
				if err != nil {
					continue
				}
				gwPrefix, err := ip.Prefix(ones)
				if err != nil || ipPrefix != gwPrefix {
					continue
				}
				for _, i := range ifs {
					if i.Name != dev.Name {
						continue
					}
					gsInterface := GSInterface{
						Name:    i.Name,
						Gateway: gateway,
						Mask:    ipPrefix,
						Handle:  GetHandle(i.Name),
						HWAddr:  i.HardwareAddr,
						IP:      ip,
					}
					logger.Debug("Get gs iface", zap.Any("gsIface", gsInterface))
					gsInterfaces = append(gsInterfaces, gsInterface)
				}

			}
		}
	}
	return &gsInterfaces
}

var gsInterface = getActiveInterfaces()

func GetActiveInterfaces() *[]GSInterface {
	return gsInterface
}
