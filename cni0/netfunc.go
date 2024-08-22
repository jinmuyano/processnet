package cni0

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/google/gopacket"
)

var (
	errNotFound     = errors.New("socketid not found")
	errProcNotFound = errors.New("proc not found")
)

const (
	defaultQueueSize      = 2000000 // 2w
	defaultWorkerNum      = 1       // usually one worker is enough.
	defaultSyncInterval   = time.Duration(1 * time.Second)
	defaultCaptureNum     = 1                                                //抓包持续时间
	defaultCaptureTimeout = time.Duration(1*time.Second) * defaultCaptureNum //抓包持续时间
)

func NewNetflow(processKeywords []string, serviceAddr map[string]string, isAllConn bool, isRecordPublic bool) (*Netflow, error) {

	ips, devs := parseIpaddrsAndDevices() //获取服务器eth0 ip和设备
	// 打印ip和设备
	if 0 == len(devs) {
		fmt.Println("error :no device found")
		return nil, errors.New("no device found")
	}

	fmt.Println("ips:", ips, "devs:", devs)

	var (
		ctx, cancel = context.WithCancel(context.Background())
	)
	// 更新进程信息

	nf := &Netflow{
		ctx:            ctx,
		cancel:         cancel, //cancle ctx
		bindIPs:        ips,
		bindDevices:    devs,
		qsize:          defaultQueueSize,      //2w
		workerNum:      defaultWorkerNum,      //1
		captureTimeout: defaultCaptureTimeout, //抓10s就不抓了
		syncInterval:   defaultSyncInterval,   //1s
		pcapFileName:   "",
		// procKeywords:   processKeywords,
		ServiceAddr:    serviceAddr,
		IsAllConn:      isAllConn,
		IsRecordPublic: isRecordPublic,
	}

	nf.packetQueue = make(chan gopacket.Packet, nf.qsize) //2w大小
	nf.delayQueue = make(chan *delayEntry, nf.qsize)      //2w大小
	nf.processHash = NewProcessController(nf.ctx)         //进程对象集合---对应网络数据
	nf.processHash.procKeywords = processKeywords
	nf.PodIpPidHash = NewMapping()

	return nf, nil
}

func (nf *Netflow) configureCgroups() error {
	if nf.cpuCore == 0 && nf.memMB == 0 {
		return nil
	}

	cg := cgroupsLimiter{}
	pid := os.Getpid() //获取当前进程pid

	err := cg.configure(pid, nf.cpuCore, nf.memMB) //配置cgroups
	nf.exitFunc = append(nf.exitFunc, func() {
		cg.free()
	})

	return err
}

func (nf *Netflow) Start() error {

	// linux cpu/mem by cgroup
	// start workers
	fmt.Println("Netflow) Start(")
	err := nf.rescanResouce()

	if err != nil {
		fmt.Println("error rescanResouce ", err)
		return err
	}

	dictAddrPid := nf.processHash.dictAddrPid
	for addr := range dictAddrPid {
		nf.bindIPs[addr] = nullObject{}
	}
	fmt.Println("bindIPs:", nf.bindIPs)

	go nf.startNetworkSniffer() //shumei:抓取数据包,整理好,放入队列,消费队列
	go nf.startResourceSyncer() //shumei:统计数据,进程信息,网络连接信息   消费抓到的数据包

	return nil
}

func (nf *Netflow) rescanResouce() error {
	// 核心方法,抓包前调用,刷新进程数据
	fmt.Println("rescanResouce")
	err := nf.processHash.Rescan()

	// wg.Go(func() error {

	// 	return nf.rescanConns() //读取/proc/net/tcp文件,关联地址和socketid  //connInodeHash  Inode <-> addr
	// })
	// wg.Go(func() error {
	// 	return nf.rescanProcessInodes() //获取进程对应的所有socket-id,及进程基础信息 //inodePidMap Inode <-> pid
	// })
	// 在这里更新pid和容器ip关系

	return err
}

func (nf *Netflow) startNetworkSniffer() {
	// time.Sleep(time.Millisecond * 100) //等待同步socketip

	for dev := range nf.bindDevices { //eth0
		go nf.captureDevice(dev) //抓指定网卡包,放入队列
	}

	for i := 0; i < nf.workerNum; i++ { //1
		go nf.loopHandlePacket() //消费数据包.整理,并发数1
	}

	nf.timer = time.AfterFunc(nf.captureTimeout, //控制抓包时长
		func() {
			nf.Stop()
		},
	)
}

func (nf *Netflow) startResourceSyncer() {
	var (
		ticker   = time.NewTicker(nf.syncInterval) //1s同步一次
		entry    *delayEntry
		lastTime time.Time
	)

	// first run at the beginning
	// nf.rescanResouce()

	for {
		select {
		case <-nf.ctx.Done(): //没问题
			return
		case <-ticker.C:
			nf.rescanResouce()
			lastTime = time.Now()

			// after rescan, handle undo entries,处理延迟队列中的数据包
			for {
				if entry == nil {
					entry = nf.consumeDelayQueue() //获取解析好的,数据包
				}
				// queue is empty
				if entry == nil {
					break
				}

				// only hanlde entry before rescan.只处理扫描连接前的包  如果获取到 数据包的时间戳在,扫描完连接表时间之后的包则退出
				if entry.timestamp.After(lastTime) {
					log.Println("only hanlde entry before rescan")
					break
				}

				err := nf.handleDelayEntry(entry) //处理未匹配进程的数据包,处理失败则再处理一次,再次失败则放弃
				if err != nil {
					// time.Sleep(time.Second * 1)
					// nf.logDebug("[error]处理延迟数据包失败", entry.addr, entry.length)
					nf.rescanResouce()
					err = nf.handleDelayEntry(entry)
					if err != nil {
						log.Println("[error]处理延迟数据包失败", entry.addr, entry.length)
					}
				} else {
					log.Println("处理延迟数据包成功", entry.addr, entry.length)
				}

				entry = nil
			}
		}
	}
}

func (nf *Netflow) isBindIPs(ipa string) bool {
	_, ok := nf.bindIPs[ipa]
	return ok
}

// 将处理好的数据包数据放到delay队列处理
func (nf *Netflow) increaseTraffic(addr string, length int64, side sideOption) error {
	// 这里可以拆分流量,有进程,有地址
	proc, err := nf.getProcessByAddrPort(addr)

	if err != nil {
		if err == errProcNotFound {
			fmt.Println("errProcNotFound increaseTraffic", addr, length, side)
			return err
		}
		// socketid没找到
		den := &delayEntry{
			timestamp: time.Now(),
			times:     0,
			addr:      addr,
			length:    length,
			side:      side,
		}
		nf.pushDelayQueue(den) //根据ip地址找进程,找不到进程,则放到delay队列中,再次处理
		return err
	}
	if proc == nil {
		return errProcNotFound
	}

	nf.increaseProcessTraffic(proc, length, side, addr)
	return nil
}

func (nf *Netflow) pushDelayQueue(de *delayEntry) {
	select {
	case nf.delayQueue <- de:
	default:
		// if q is full, drain actively .
	}
}

func (nf *Netflow) consumeDelayQueue() *delayEntry {
	select {
	case <-nf.ctx.Done(): //好像有问题
		return nil

	case den := <-nf.delayQueue:
		return den

	default:
		return nil
	}
}

// 给进程增加包大小长度
func (nf *Netflow) increaseProcessTraffic(proc *Process, length int64, side sideOption, addr string) error {
	// 处理延迟和实时数据包都是这个函数
	// fmt.Println(length, addr, side, proc.Pid)
	switch side {
	case inputSide:
		proc.IncreaseInput(length, addr, nf.ServiceAddr, nf.IsAllConn, nf.IsRecordPublic)
	case outputSide:
		proc.IncreaseOutput(length, addr, nf.ServiceAddr, nf.IsAllConn, nf.IsRecordPublic)
	}
	return nil
}

// 根据数据包大小对应的地址,找到进程
func (nf *Netflow) handleDelayEntry(entry *delayEntry) error {
	proc, err := nf.getProcessByAddrPort(entry.addr) //通过数据包地址获取进程id
	if err != nil {
		return err
	}

	nf.increaseProcessTraffic(proc, entry.length, entry.side, entry.addr) //为进程添加包大小
	return nil
}

func (nf *Netflow) getProcessByAddrPort(addrport string) (*Process, error) {
	// addr--->pid---->process
	// pid := nf.PodIpPidHash.Get(addr) //通过地址获取socketid,有很多外部访问本地端口的短连接获取不到socketid,说明连接很短,没有socketid
	// if len(pid) == 0 {
	// 	return nil, errNotFound
	// }
	// pid := nf.processHash.GetPidByAddr(addr)

	proc := nf.processHash.getProcessByAddrPort(addrport) //通过socketid,获取进程,有socketid一般都能找到进程,除非不是进程的socketid,说明socketid都拿到了
	if proc == nil {
		return nil, errProcNotFound //找到socketid,没找到进程就不放入延迟队列了
	}

	return proc, nil
}

func (nf *Netflow) GetProcess(pid int, recentSeconds int) (*Process, error) {
	if recentSeconds > maxRingSize {
		return nil, errors.New("[error] windows interval must <= 15")
	}

	// nf.processHash.Sort(recentSeconds)
	proc := nf.processHash.GetProcess(pid, recentSeconds)
	if proc == nil {
		return nil, errors.New("[error] process not found")
	}
	// prank := nf.processHash.GetRank(limit)
	return proc, nil
}

func (nf *Netflow) Stop() {
	log.Println("退出抓包")
	nf.cancel() //取消抓包
	nf.finalize()

	if nf.pcapFile != nil {
		nf.pcapFile.Close()
	}
}

func (nf *Netflow) finalize() {
	if nf.timer != nil {
		nf.timer.Stop() //退出startNetworkSniffer
	}
	for _, fn := range nf.exitFunc {
		fn()
	}
}
