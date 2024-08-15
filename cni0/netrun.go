package cni0

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcapgo"
	pnet "github.com/jinmuyano/processnet"
	"github.com/mitchellh/go-ps"
)

type sideOption int

var (
	Nf *Netflow //启动创建,退出关闭

)

const (
	inputSide sideOption = iota
	outputSide
)

type delayEntry struct {
	// meta
	timestamp time.Time
	times     int

	// data
	addr   string
	length int64
	side   sideOption
}

type nullObject = struct{}

type Netflow struct {
	ctx    context.Context
	cancel context.CancelFunc

	PodIpPidHash *Mapping
	processHash  *processController
	workerNum    int
	qsize        int

	// for update action
	delayQueue  chan *delayEntry     //包计算好长度后,存放队列
	packetQueue chan gopacket.Packet //抓包存放队列

	bindIPs        map[string]nullObject // read only
	bindDevices    map[string]nullObject // read only
	counter        int64
	captureTimeout time.Duration
	syncInterval   time.Duration
	pcapFilter     string // for pcap filter

	pcapFileName string
	pcapFile     *os.File
	pcapWriter   *pcapgo.Writer

	// for cgroup
	cpuCore float64
	memMB   int

	exitFunc []func()
	timer    *time.Timer

	ServiceAddr map[string]string // 统计那些指定服务地址的流量
	IsAllConn   bool              // 是否统计所有连接流量
}

func netflowStart(client *CniPacketClient) {
	var err error

	Nf, err = NewNetflow(client.conf.ProcessKeyword, client.conf.ServiceAddr, client.conf.IsAllConn) //new对象,接口类型赋值,空的
	if err != nil {
		log.Println("创建netflow对象Nf失败", err)
	}

	err = Nf.Start() //启动调用,装填数据
	if err != nil {
		log.Println("Nf对象启动失败", err)
	}

	var (
		// sigch = make(chan os.Signal, 1) //接收一些操作系统信号
		// timeout = time.NewTimer(12 * time.Second) //12s后结束进程,抓包持续时间为10s
		timeout = time.NewTimer(defaultCaptureTimeout) //10s后结束进程,抓包持续时间为10s,设置为和抓包时间一致,抓包前等了2s,这里会结束的更快
	)

	// signal.Notify(sigch,
	// 	syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT,
	// 	syscall.SIGHUP, syscall.SIGUSR1, syscall.SIGUSR2,
	// )

	defer func() {
		stop(client)
	}()

	// 阻塞住,等待接收超时和退出信号
	for {
		select {
		// case <-sigch:
		// 	return

		case <-timeout.C:
			// fmt.Println("时间到,netflow结束")
			return
		}
	}
}

func stop(client *CniPacketClient) {
	if Nf == nil {
		fmt.Println("[error]netflow is nil")
		return
	}
	time.Sleep(100 * time.Millisecond)
	// 解析包速度
	// 等待10ms
	processes, err := ps.Processes()
	if err != nil {
		fmt.Println("cron readprocess [error]", err)
		return
	}
	var pidList []int // 当前进程id
	for _, p := range processes {
		// 过滤进程
		ismatch := isMatchProcess(p.Executable(), client.conf.ProcessKeyword)
		if ismatch {
			pid := p.Pid()
			pidList = append(pidList, pid)
		}
	}

	// 打印processMap
	for _, pid := range pidList {
		fmt.Println("stop 开始解析进程对应的网络带宽--->", pid)
	}

	result := pnet.Result{}
	for _, pid := range pidList {
		// 解析 包速度
		proc, err := Nf.GetProcess(pid, defaultCaptureNum) //关闭前解析包速度
		if err != nil {
			fmt.Println("stop [error]Nf.GetProcess,--->没获取到进程的网络信息", err)
		} else {
			fmt.Println("stop 收集到pid:", pid, "的解析速度")
			// netMapNew[pid] = proc.TrafficStats
			result[pid] = pnet.BandWidth{
				InRate:     proc.TrafficStats.InRate,
				OutRate:    proc.TrafficStats.OutRate,
				InService:  proc.InServiceNet,
				OutService: proc.OutServiceNet,
			}
		}
	}

	client.setBandWidth(result)

}
