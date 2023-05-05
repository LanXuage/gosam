package icmp_test

import (
	"gscan/common"
	"gscan/icmp"
	"net/netip"
	"testing"
	"time"
)

func TestICMPScanPrefix(t *testing.T) {
	i := icmp.New()
	defer i.Close()
	// ipList := []string{""}
	ipCIDR := "172.20.10.1/24"

	prefix, err := netip.ParsePrefix(ipCIDR)

	if err != nil {
		t.Log(err)
	}

	go func() {
		for res := range i.ResultCh {
			t.Log(res)
		}
	}()
	// t.Log(i.IPList)
	i.ScanListByPrefix(prefix)
	time.Sleep(i.Timeout)
	t.Log((*i.Results).Items())
	t.Log((*i.Results).Count())
}

func TestICMPScanList(t *testing.T) {
	i := icmp.New()
	defer i.Close()

	testIPList := []string{"13.107.21.200", "120.78.212.208",
		"183.6.50.84", "192.168.31.1", "192.168.31.100",
		"14.119.104.189", "106.14.112.92", "192.168.1.9",
		"192.168.2.134", "192.168.2.110", "192.168.2.200",
	}

	dstIPList := common.IPList2NetIPList(testIPList)
	go func() {
		for res := range i.ResultCh {
			t.Log(res)
		}
	}()

	i.ScanList(dstIPList)

	time.Sleep(time.Second * 3)
	t.Log(i.IPList)
	t.Log((*i.Results).Items())
}

func TestICMPScanOne(t *testing.T) {
	i := icmp.New()
	defer i.Close()

	testIP := "172.20.10.1"

	dstIP, err := netip.ParseAddr(testIP)
	if err != nil {
		return
	}
	go func() {
		for res := range i.ResultCh {
			t.Log(res)
		}
	}()

	i.ScanOne(dstIP)

	time.Sleep(time.Second * 1)
	t.Log(i.IPList)
	t.Log((*i.Results).Items())
}
