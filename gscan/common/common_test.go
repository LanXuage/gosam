package common

import (
	"net"
	"testing"
)

func Test_Common(t *testing.T) {
	gateway := net.ParseIP("192.168.0.1")
	netmask := uint32(0xffffff00)
	ip := net.ParseIP("192.168.0.45")

	if CheckIPisIPNet(ip, gateway, netmask) {
		t.Log("Fuck")
	} else {
		t.Log("Fuck2")
	}

}