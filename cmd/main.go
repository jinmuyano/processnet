package main

import (
	"fmt"
	"os"
	"sort"
	"strconv"

	"github.com/jinmuyano/processnet/eth0"
)

func main() {

	// TODO: Implement the application.
	// 统计本机上所有java进程流量top
	// 还要根据这些ip,去查ip端口属于哪个服务
	args := os.Args
	if len(args) == 1 {
		fmt.Println("请添加参数,进程id")
	}
	pid := args[1]
	fmt.Println("pid:", pid)
	// pid转int
	pidInt, _ := strconv.Atoi(pid)

	config := eth0.NewPacketClientConfig()
	config.ProcessKeyword = []string{"java", "curl"}
	config.IsAllConn = true
	// config.ServiceAddr = map[string]string{
	// 	"192.168.165.xx:30002":  "zk-1",
	// 	"192.168.162.1xx:30002": "zk-2",
	// 	"192.168.162.1xx:30003": "zk-3",
	// }
	client := eth0.NewPacketClient(config)
	result := client.Run()
	pidnet := result[pidInt]
	// 服务入带宽排序

	type KeyValue struct {
		Key   string
		Value int64
	}

	// -----入流量
	fmt.Println("入流量")
	var in_pairs []KeyValue
	for k, v := range pidnet.InService {
		in_pairs = append(in_pairs, KeyValue{Key: k, Value: v})
	}

	// 根据成绩对切片进行排序
	sort.Slice(in_pairs, func(i, j int) bool {
		return in_pairs[i].Value > in_pairs[j].Value // 降序排序
	})

	// 遍历排序后的切片，打印
	var in int64
	for _, pair := range in_pairs {
		fmt.Printf("in:%s-> %fmb/s\n", pair.Key, float64(pair.Value)/1024/1024)
		in += pair.Value
	}
	fmt.Println("进程入流量:", float64(in)/1024/1024, "mb/s")

	fmt.Println("----------------------------------")

	// -----出流量
	fmt.Println("出流量")
	var out_pairs []KeyValue
	for k, v := range pidnet.OutService {
		out_pairs = append(out_pairs, KeyValue{Key: k, Value: v})
	}
	// 根据成绩对切片进行排序
	sort.Slice(out_pairs, func(i, j int) bool {
		return out_pairs[i].Value > out_pairs[j].Value // 降序排序
	})
	// 遍历排序后的切片，打印
	var out int64
	for _, pair := range out_pairs {
		fmt.Printf("out:%s-> %fmb/s\n", pair.Key, float64(pair.Value)/1024/1024)
		out += pair.Value
	}

	fmt.Println("进程出流量:", float64(out)/1024/1024, "mb/s")

	// 打印进程入流量
	fmt.Println("进程入流量:", float64(pidnet.InRate)/1024/1024, "mb/s")
	// fmt.Println("进程入流量:", float64(pidnet.InRate)/1024/1024, "mb/s")
	// 打印进程出流量
	fmt.Println("进程出流量:", float64(pidnet.OutRate)/1024/1024, "mb/s")
	// fmt.Println("进程出流量:", float64(pidnet.OutRate)/1024/1024, "mb/s")

}
