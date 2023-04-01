package port

import (
	"fmt"
	"gscan/common"
	"gscan/common/ports"
	"testing"
	"time"
)

func Test_PortScan(t *testing.T) {
	p := New()
	defer p.Close()

	ipList := []string{
		"192.168.0.1",
		"192.168.2.2",
		"192.168.2.3",
		"192.168.2.4",
		"192.168.2.5",
		"192.168.2.45",
		"23.224.202.186",
	}

	tmp := common.IPList2NetIPList(ipList)

	tcp := p.TCPScan(tmp)

	time.Sleep(time.Second * 5)

	ip := []uint32{}
	for ipUint32 := range tcp.Results {
		ip = append(ip, ipUint32)
	}

	for _, _ip := range ip {
		fmt.Printf("IP %s Port Scan Result:\n", common.Uint322IP(_ip))
		portsMap := tcp.Results[_ip]
		for _, port := range ports.GetDefaultPorts() {
			if portsMap[uint16(port)] {
				fmt.Printf("%d is seem to Open\n", port)
			} else {
				fmt.Printf("%d is seem to Close\n", port)
			}
		}
		fmt.Printf("--------------------------------\n")
	}

}
