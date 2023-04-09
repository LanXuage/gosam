package port

import (
	"fmt"
	"gscan/common"
	"gscan/common/ports"
	"testing"
	"time"
)

func Test_PortScan(t *testing.T) {
}

func Test_HALFTCP(t *testing.T) {
	p := New()
	defer p.Close()

	ipList := []string{
		"106.14.112.92",
	}

	tmp := common.IPList2NetIPList(ipList)

	tcp := p.TCPScan(tmp, TYPE_HALFTCP)

	time.Sleep(time.Second * 5)

	ip := []uint32{}
	for ipUint32 := range tcp.Results {
		ip = append(ip, ipUint32)
	}
	fmt.Println(tcp.Results)

	for _, _ip := range ip {
		fmt.Printf("IP %s Port Scan Result:\n", common.Uint322IP(_ip))
		portsMap := tcp.Results[_ip]
		for _, port := range *ports.GetDefaultPorts() {
			if portsMap[port] {
				fmt.Printf("%d is seem to Open\n", port)
			} else {
				fmt.Printf("%d is seem to Close\n", port)
			}
		}
		fmt.Printf("--------------------------------\n")
	}
}

func Test_FULLTCP(t *testing.T) {
	p := New()
	defer p.Close()

	ipList := []string{
		"106.14.112.92",
	}

	tmp := common.IPList2NetIPList(ipList)

	tcp := p.TCPScan(tmp, TYPE_FULLTCP)

	time.Sleep(time.Second * 5)

	ip := []uint32{}
	for ipUint32 := range tcp.Results {
		ip = append(ip, ipUint32)
	}
	fmt.Println(tcp.Results)

	for _, _ip := range ip {
		fmt.Printf("IP %s Port Scan Result:\n", common.Uint322IP(_ip))
		portsMap := tcp.Results[_ip]
		for _, port := range *ports.GetDefaultPorts() {
			if portsMap[port] {
				fmt.Printf("%d is seem to Open\n", port)
			} else {
				fmt.Printf("%d is seem to Close\n", port)
			}
		}
		fmt.Printf("--------------------------------\n")
	}
}

func Test_UDP(t *testing.T) {
	p := New()
	defer p.Close()

	ipList := []string{
		"106.14.112.92",
		"192.168.2.155",
	}

	tmp := common.IPList2NetIPList(ipList)

	udp := p.UDPScan(tmp)

	time.Sleep(time.Second * 5)

	ip := []uint32{}
	for ipUint32 := range udp.Results {
		ip = append(ip, uint32(ipUint32))
	}

	fmt.Println(ip)

}
