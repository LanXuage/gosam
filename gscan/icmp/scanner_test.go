package icmp

import (
	"gscan/common"
	"testing"
)

func Test_ICMPScanner(t *testing.T) {
	i := New()
	defer i.Close()

	ipList := []string{"13.107.21.200", "120.78.212.208", "183.6.50.84"}

	tmp := common.IPList2NetIPList(ipList)

	<-i.ScanList(tmp)

}
