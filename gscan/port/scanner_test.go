package port

import (
	"fmt"
	"gscan/common"
	"gscan/common/ports"
	"os"
	"testing"
	"time"
)

var testIPList = []string{
	"106.14.112.92",
	"14.119.104.189",
}

var testTCPScanPorts = *ports.GetDefaultPorts()

func Test_HALFTCP(t *testing.T) {
	os.Setenv("GSCAN_LOG_LEVEL", "development")
	p := New()
	defer p.Close()

	tmp := common.IPList2NetIPList(testIPList)
	tcp := p.TCPScan(tmp, testTCPScanPorts, TYPE_HALFTCP)

	time.Sleep(tcp.Timeout)

	ip := []uint32{}
	for ipUint32 := range tcp.Results {
		ip = append(ip, ipUint32)
	}
	t.Log(tcp.Results)

	for _, _ip := range ip {
		t.Logf("IP %s Port Scan Result:\n", common.Uint322IP(_ip))
		portsMap := tcp.Results[_ip]
		for _, port := range testTCPScanPorts {
			if portsMap[port] {
				t.Logf("%d is seem to Open\n", port)
			} else {
				t.Logf("%d is seem to Close\n", port)
			}
		}
		fmt.Printf("--------------------------------\n")
	}
}

func Test_FULLTCP(t *testing.T) {
	os.Setenv("GSCAN_LOG_LEVEL", "development")
	p := New()
	defer p.Close()

	tmp := common.IPList2NetIPList(testIPList)

	tcp := p.TCPScan(tmp, testTCPScanPorts, TYPE_FULLTCP)

	time.Sleep(tcp.Timeout)

	ip := []uint32{}
	for ipUint32 := range tcp.Results {
		ip = append(ip, ipUint32)
	}
	t.Log(tcp.Results)

	for _, _ip := range ip {
		t.Logf("IP %s Port Scan Result:\n", common.Uint322IP(_ip))
		portsMap := tcp.Results[_ip]
		for _, port := range testTCPScanPorts {
			if portsMap[port] {
				t.Logf("%d is Open\n", port)
			} else {
				t.Logf("%d is Close\n", port)
			}
		}
		fmt.Printf("--------------------------------\n")
	}
}

func Test_UDP(t *testing.T) {
	os.Setenv("GSCAN_LOG_LEVEL", "development")
	p := New()
	defer p.Close()

	tmp := common.IPList2NetIPList(testIPList)

	udp := p.UDPScan(tmp)

	time.Sleep(udp.Timeout)

	ip := []uint32{}
	for ipUint32 := range udp.Results {
		ip = append(ip, uint32(ipUint32))
	}

	fmt.Println(ip)

}
