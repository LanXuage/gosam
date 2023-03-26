package icmp

import (
	"fmt"
	"gscan/common"
	"testing"
)

func Test_ICMPScanner(t *testing.T) {
	i := New()
	defer i.Close()
	
	ipList := []string{"13.107.21.200", "120.78.212.208",
		"183.6.50.85", "192.168.2.1", "192.168.2.100"}

	tmp := common.IPList2NetIPList(ipList)

	//fmt.Println(i.AScanner.AMap)

	for res := range i.ScanList(tmp) {
		fmt.Println(res)
	}

}

