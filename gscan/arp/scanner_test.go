package arp

import (
	"fmt"
	"testing"
)

func Test_ARPScanner(t *testing.T) {
	a := New()
	defer a.Close()
	for result := range a.ScanLocalNet() {
		fmt.Println(result)
	}
}
