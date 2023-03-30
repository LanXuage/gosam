package icmp

import (
	"fmt"
	"gscan/common"
	"testing"
	"time"
)

func Test_ICMPScanner(t *testing.T) {
	i := New()
	defer i.Close()

	ipList := []string{"13.107.21.200", "120.78.212.208",
		"183.6.50.84", "192.168.0.1", "192.168.0.100", "183.6.50.85", "183.6.56.69", "183.6.56.68"}

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
