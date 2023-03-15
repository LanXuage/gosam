package common

import (
	"net"
	"strings"
)

func GetOuiPrefix(mac net.HardwareAddr) (string, string) {
	ret1 := strings.ToUpper(strings.Replace(mac.String()[:8], ":", "", -1))
	ret2 := strings.ToUpper(strings.Replace(mac.String()[:13], ":", "", -1))
	return ret1, ret2
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
