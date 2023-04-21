package arp_test

import (
	"gscan/arp"
	"os"
	"testing"
	"time"
)

func Test_ARPScanner(t *testing.T) {
	os.Setenv("GSCAN_LOG_LEVEL", "development")
	a := arp.GetARPScanner()
	defer a.Close()
	go func() {
		for result := range a.ScanLocalNet() {
			t.Log(result)
		}
	}()
	time.Sleep(5 * time.Second)
	t.Log(a.AMap.Items())
}
