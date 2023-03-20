package common

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
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

func PacketToIPv4(packet gopacket.Packet) net.IP{
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		if ip != nil {
			return ip.SrcIP
		}
	}
	return net.IPv4zero
}

func GetHandle(deviceName string) *pcap.Handle {
	handle, err := pcap.OpenLive(deviceName, 65535, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	return handle
}