package arp

import (
	"fmt"
	"testing"
	"time"
)

func Test_ARPScanner(t *testing.T) {
	a := New()
	defer a.Close()
	go func() {
		for result := range a.ScanLocalNet() {
			fmt.Println(result)
		}
	}()
	time.Sleep(30 * time.Second)
	t.Log(a.AMap)
}
