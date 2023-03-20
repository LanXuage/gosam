package icmp

import (
	"net"
	"testing"
)

func Test_ICMPScanner(t *testing.T) {
	i := New()
	defer i.Close()

	tmp := []net.IP{
		{183,6,50,84},
	}

	<-i.Scan(tmp)

}
