package icmp

import (
	"net"
	"testing"
)

func Test_ICMPScanner(t *testing.T) {
	i := New()
	defer i.Close()

	tmp := []net.IP{
		{14,119,104,189},
		{183,6,56,68},
	}

	<-i.Scan(tmp)

}
