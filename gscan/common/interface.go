package common

import (
	"net"

	"github.com/google/gopacket/pcap"
	"go.uber.org/zap"
)

type GSInterface struct {
	Name    string           // 接口名称
	Gateway net.IP           // 接口网关IP
	Mask    uint32           // 接口掩码
	HWAddr  net.HardwareAddr // 接口物理地址
	IP      net.IP           // 接口IP
	Handle  *pcap.Handle     // 接口pcap句柄
}

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
				maskUint32 := IPMask2Uint32(addr.Netmask)
				if !IsSameLAN(addr.IP, gateway, maskUint32) {
					continue
				}
				for _, i := range ifs {
					if i.Name != dev.Name {
						continue
					}
					gsInterface := GSInterface{
						Name:    i.Name,
						Gateway: gateway,
						Mask:    maskUint32,
						Handle:  GetHandle(i.Name),
						HWAddr:  i.HardwareAddr,
						IP:      addr.IP,
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
