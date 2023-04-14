package icmp_test

import (
	"fmt"
	"gscan/common"
	"gscan/icmp"
	"testing"
	"time"
)

func Test_ICMPScanner(t *testing.T) {
	i := icmp.New()
	defer i.Close()

	ipList := []string{"13.107.21.200", "120.78.212.208",
		"183.6.50.84", "192.168.31.1", "192.168.31.100"}

	tmp := common.IPList2NetIPList(ipList)

	go func() {
		for res := range i.ScanList(tmp) {
			if res.IsActive {
				fmt.Printf("%s is Active\n", res.IP)
			}
			if !res.IsActive {
				fmt.Printf("%s is Inactive\n", res.IP)
			}
		}
	}()

	time.Sleep(time.Second * 5)
	t.Log(i.Results)
}
