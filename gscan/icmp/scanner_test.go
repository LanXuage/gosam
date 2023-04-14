package icmp

import (
	"gscan/common"
	"os"
	"testing"
	"time"
)

func Test_ICMPScanner(t *testing.T) {
	os.Setenv("GSCAN_LOG_LEVEL", "development")
	i := New()
	defer i.Close()

	testIPList := []string{"13.107.21.200", "120.78.212.208",
		"183.6.50.84", "192.168.31.1", "192.168.31.100",
		"14.119.104.189"}

	tmp := common.IPList2NetIPList(testIPList)

	go func() {
		i.ScanList(tmp)
	}()

	time.Sleep(i.Timeout)

	ip := []uint32{}
	for ipUint32 := range i.Results {
		ip = append(ip, ipUint32)
	}

	for idx := 0; idx < len(i.Results); idx++ {
		if i.Results[ip[idx]] {
			t.Logf("%s is Active\n", common.Uint322IP(ip[idx]))
		} else {
			t.Logf("%s is Inactive\n", common.Uint322IP(ip[idx]))
		}
	}

	t.Log(i.Results)
}
