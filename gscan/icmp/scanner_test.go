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
		"183.6.50.84", "192.168.31.1", "192.168.31.100"}

	tmp := common.IPList2NetIPList(ipList)

	go func() {
		i.ScanList(tmp)
	}()

	time.Sleep(time.Second * 5)

	ip := []uint32{}
	for ipUint32 := range i.Results {
		ip = append(ip, ipUint32)
	}

	for idx := 0; idx < len(i.Results); idx++ {
		if i.Results[ip[idx]] {
			fmt.Printf("%s is Active\n", common.Uint322IP(ip[idx]))
		} else {
			fmt.Printf("%s is Inactive\n", common.Uint322IP(ip[idx]))
		}
	}

	t.Log(i.Results)
}
