package common

import (
	"fmt"
	"testing"

	"github.com/google/gopacket"
)

type TestRes struct {
	Name string
}

func test(packet gopacket.Packet) interface{} {
	fmt.Println(packet)
	return TestRes{
		Name: "test",
	}
}

func TestMain(t *testing.T) {
	r := GetReceiver()
	rCh := r.Register("test", test)
	for r := range rCh {
		if res, ok := r.(TestRes); ok {
			t.Logf("got res %s", res.Name)
		}
	}
}
