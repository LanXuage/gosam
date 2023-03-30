package port

import (
	"gscan/common"
	"testing"
	"time"
)

func Test_PortScan(t *testing.T) {
	p := New()
	defer p.Close()

	ipList := []string{
		"192.168.0.1",
		"192.168.0.2",
		"192.168.0.3",
		"192.168.0.4",
		"192.168.0.5",
		"192.168.0.45",
	}

	tmp := common.IPList2NetIPList(ipList)

	p.ScanList(tmp)

	time.Sleep(time.Second * 5)
}
