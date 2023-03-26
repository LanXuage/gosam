package common

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"sync"
)

type Receiver struct {
	State     uint8
	Lock      sync.Mutex
	HookFuns  map[string]func(gopacket.Packet) interface{}
	ResultChs map[string]chan interface{}
}

func newReceiver() *Receiver {
	r := &Receiver{
		State:     0,
		HookFuns:  make(map[string]func(gopacket.Packet) interface{}),
		ResultChs: make(map[string]chan interface{}),
	}
	r.init()
	return r
}

func (r *Receiver) init() {
	for _, gsInterface := range *GetActiveInterfaces() {
		src := gopacket.NewPacketSource(gsInterface.Handle, layers.LayerTypeEthernet)
		fmt.Printf("start gsInterface %s\n", gsInterface.Name)
		go r.recv(src.Packets())
	}
}

func (r *Receiver) recv(packets <-chan gopacket.Packet) {
	for packet := range packets {
		for name, hookFun := range r.HookFuns {
			go func(name string, hookFun func(packet gopacket.Packet) interface{}) {
				r.ResultChs[name] <- hookFun(packet)
			}(name, hookFun)
		}
	}
}

func (r *Receiver) Register(name string, hookFun func(gopacket.Packet) interface{}) chan interface{} {
	if _, ok := r.ResultChs[name]; !ok {
		r.Lock.Lock()
		defer r.Lock.Unlock()
		r.ResultChs[name] = make(chan interface{}, 10)
		r.HookFuns[name] = hookFun
	}
	return r.ResultChs[name]
}

func (r *Receiver) Unregister(name string) {
	if _, ok := r.ResultChs[name]; !ok {
		r.Lock.Lock()
		defer r.Lock.Unlock()
		delete(r.ResultChs, name)
		delete(r.HookFuns, name)
	}
}

var instance = newReceiver()

func GetReceiver() *Receiver {
	return instance
}
