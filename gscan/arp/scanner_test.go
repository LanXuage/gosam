package arp

import (
	"fmt"
	"testing"
	"time"

	"go.uber.org/zap"
)

func Test_ARPScanner(t *testing.T) {
	zap.NewAtomicLevel().SetLevel(zap.DebugLevel)
	a := New()
	defer a.Close()
	go func() {
		for result := range a.ScanLocalNet() {
			fmt.Println(result)
		}
	}()
	time.Sleep(5 * time.Second)
	t.Log(a.AMap)
}
