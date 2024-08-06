package main

import (
	"fmt"
	"testing"
	"time"

	"github.com/jinmuyano/processnet/cni0"
	"github.com/jinmuyano/processnet/eth0"
)

// go test -run Test_eth0
func TestCronEth0(t *testing.T) {
	config := eth0.NewPacketClientConfig()
	config.Interval = "10s" //抓包频率
	config.ProcessKeyword = []string{"java", "curl"}
	// config.ServiceAddr = map[string]string{
	// 	"192.168.165.xx:30002":  "zk-1",
	// 	"192.168.162.1xx:30002": "zk-2",
	// 	"192.168.162.1xx:30003": "zk-3",
	// }
	client := eth0.NewPacketClient(config)
	defer client.Stop()
	// packet := pnet.NewPacket(client)
	client.Start()
	for {
		time.Sleep(time.Second * 5)
		fmt.Println("get band width")
		data := client.GetBandWidth()
		fmt.Println("data:", data)
		time.Sleep(time.Second * 25)
	}

}

// go test -run Test_cni0
func TestCronCni0(t *testing.T) {
	config := cni0.NewPacketClientConfig()
	config.Interval = "10s" //抓包频率
	config.ProcessKeyword = []string{"java", "curl"}
	// config.ServiceAddr = map[string]string{
	// 	"192.168.165.xx:30002":  "zk-1",
	// 	"192.168.162.1xx:30002": "zk-2",
	// 	"192.168.162.1xx:30003": "zk-3",
	// }
	client := cni0.NewPacketClient(config)
	// packet := pnet.NewPacket(client)
	defer client.Stop()
	client.Start()
	for {
		time.Sleep(time.Second * 5)
		fmt.Println("get band width")
		data := client.GetBandWidth()
		fmt.Println("data:", data)
		time.Sleep(time.Second * 25)
	}
}

func TestCni0(t *testing.T) {
	config := cni0.NewPacketClientConfig()
	config.ProcessKeyword = []string{"java", "curl"}
	// config.ServiceAddr = map[string]string{
	// 	"192.168.165.xx:30002":  "zk-1",
	// 	"192.168.162.1xx:30002": "zk-2",
	// 	"192.168.162.1xx:30003": "zk-3",
	// }
	client := cni0.NewPacketClient(config)
	result := client.Run()
	fmt.Print(result)
}

func TestEth0(t *testing.T) {
	config := eth0.NewPacketClientConfig()
	config.ProcessKeyword = []string{"java", "curl"}
	// config.ServiceAddr = map[string]string{
	// 	"192.168.165.xx:30002":  "zk-1",
	// 	"192.168.162.1xx:30002": "zk-2",
	// 	"192.168.162.1xx:30003": "zk-3",
	// }
	client := eth0.NewPacketClient(config)
	result := client.Run()
	fmt.Print(result)
}
