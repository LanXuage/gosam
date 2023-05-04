package port_test

import (
	"gscan/common"
	"gscan/common/ports"
	"gscan/port"
	"os"
	"testing"
	"time"
)

var testIPList = []string{"13.107.21.200", "120.78.212.208",
	"183.6.50.84", "192.168.31.1", "192.168.31.100",
	"14.119.104.189", "106.14.112.92", "192.168.1.9",
	"192.168.2.134", "192.168.2.110", "192.168.2.200",
}

var testTCPScanPorts = *ports.GetDefaultPorts()

func TestHalfTCP(t *testing.T) {
	os.Setenv("GSCAN_LOG_LEVEL", "development")
	p := port.New()
	defer p.Close()

	tmp := common.IPList2NetIPList(testIPList)
	tcp := p.TCPScan(tmp, testTCPScanPorts, 1)

	time.Sleep(tcp.Timeout)

	for _, ip := range testIPList {
		t.Logf("IP %s result:", ip)
		if portList, ok := (*tcp.Results).Get(ip); portList != nil && ok {
			for _, port := range tcp.ScanPorts {
				if status, _ := portList.Get(port.String()); status {
					t.Logf("Port %s is seem open", port)
				} else {
					t.Logf("Port %s is seem close", port)
				}
			}
		}
	}
}

func TestFullTCP(t *testing.T) {
	os.Setenv("GSCAN_LOG_LEVEL", "development")
	p := port.New()
	defer p.Close()

	tmp := common.IPList2NetIPList(testIPList)

	tcp := p.TCPScan(tmp, testTCPScanPorts, 0)

	time.Sleep(tcp.Timeout)

	for _, ip := range testIPList {
		t.Logf("IP %s result:", ip)
		if portList, ok := (*tcp.Results).Get(ip); portList != nil && ok {
			for _, port := range tcp.ScanPorts {
				if status, _ := portList.Get(port.String()); status {
					t.Logf("Port %s is open", port)
				} else {
					t.Logf("Port %s is close", port)
				}
			}
		}
	}
}

func Test_UDP(t *testing.T) {
	os.Setenv("GSCAN_LOG_LEVEL", "development")
	p := port.New()
	defer p.Close()

	tmp := common.IPList2NetIPList(testIPList)

	udp := p.UDPScan(tmp)

	time.Sleep(udp.Timeout)

	ip := []uint32{}
	for ipUint32 := range udp.Results {
		ip = append(ip, uint32(ipUint32))
	}

	t.Log(ip)

}
