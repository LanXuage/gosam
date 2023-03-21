package common

import (
	"net"
	"testing"
)

func Test_Common(t *testing.T) {
	gateway := net.ParseIP("192.168.0.1")
	netmask := uint32(0xfffffff0)
	ip := net.ParseIP("192.168.0.45")

	CheckIPisIPNet(ip, gateway, netmask)

}