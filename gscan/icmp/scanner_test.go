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
		"14.119.104.189", "106.14.112.92", "192.168.1.9",
		"192.168.2.134", "192.168.2.110", "192.168.2.200"}

	tmp := common.IPList2NetIPList(testIPList)

	go func() {
		i.ScanList(tmp)
	}()

	time.Sleep(i.Timeout)

	t.Log("ICMP Results:")
	for _, ip := range testIPList {
		if _, ok := (*i.Results).Get(ip); ok {
			t.Logf("%s is Active\n", ip)
		} else {
			t.Logf("%s is InActive\n", ip)
		}
	}
}
