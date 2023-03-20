//go:build darwin
// +build darwin

package common

import "net"

func GetGateways() []net.IP {
	return []net.IP{{192,168,0,1}}
}
