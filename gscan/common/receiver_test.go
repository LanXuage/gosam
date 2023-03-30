package common

import (
	"fmt"
	"testing"
	"time"

	"github.com/google/gopacket"
)

type TestRes struct {
	Name string
}

func test(packet gopacket.Packet) interface{} {
	//fmt.Println(packet)
	//icmpLayer := packet.Layer(layers.LayerTypeICMPv4)
	//
	//fmt.Println(icmpLayer)

	fmt.Println("test")
	return TestRes{
		Name: "test",
	}
}

func test1(packet gopacket.Packet) interface{} {
	fmt.Println("test1")

	return TestRes{
		Name: "test1",
	}
}

func TestFuck(t *testing.T) {
	r := GetReceiver()
	rCh := r.Register("test", test)
	time.Sleep(1 * time.Second)
	//fmt.Println("aaaaa")
	r.Register("test1", test1)
	for r := range rCh {
		if res, ok := r.(TestRes); ok {
			t.Logf("got res %s", res.Name)
			//close(rCh)
		}
	}

	//for r := range rCh2 {
	//	if res, ok := r.(TestRes); ok {
	//		t.Logf("got res %s",res.Name)
	//	}
	//}

}
