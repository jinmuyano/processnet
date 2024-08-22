package eth0

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"golang.org/x/sync/errgroup"
)

var (
	errNotFound     = errors.New("socketid not found")
	errProcNotFound = errors.New("proc not found")
)

type sideOption int

const (
	inputSide sideOption = iota
	outputSide
)

type Netflow struct {
	ctx    context.Context
	cancel context.CancelFunc

	connInodeHash *Mapping
	processHash   *processController
	workerNum     int
	qsize         int

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

	// for debug
	debugMode bool
	logger    LoggerInterface

	// for cgroup
	cpuCore float64
	memMB   int

	exitFunc []func()
	timer    *time.Timer

	procKeywords   []string          //统计那些进程流量的二进制命令
	ServiceAddr    map[string]string // 统计那些指定服务地址的流量
	ProcessAddrMap map[string]int    // 抓包前统计,netstat统计addr:port归属于哪个进程
	IsAllConn      bool              // 是否统计所有连接带宽
	IsRecordPublic bool              // 是否单独统计公网流量
}

type optionFunc func(*Netflow) error

// WithPcapFilter set custom pcap filter
// filter: "port 80", "src host xiaorui.cc and port 80"
func WithPcapFilter(filter string) optionFunc {
	return func(o *Netflow) error {
		if len(filter) == 0 {
			return nil
		}

		st := strings.TrimSpace(filter)
		if strings.HasPrefix(st, "and") {
			return errors.New("invalid pcap filter")
		}

		o.pcapFilter = filter
		return nil
	}
}

func WichProcKeywords(procKeywords []string) optionFunc {
	return func(o *Netflow) error {
		o.procKeywords = procKeywords
		return nil
	}
}

func WichServiceAddr(serviceAddr map[string]string) optionFunc {
	return func(o *Netflow) error {
		o.ServiceAddr = serviceAddr
		return nil
	}
}

func WichIsAllConn(isallconn bool) optionFunc {
	return func(o *Netflow) error {
		o.IsAllConn = isallconn
		return nil
	}
}

func WichIsRecordPublic(isrecordpublic bool) optionFunc {
	return func(o *Netflow) error {
		o.IsRecordPublic = isrecordpublic
		return nil
	}
}

func WithOpenDebug() optionFunc {
	return func(o *Netflow) error {
		o.debugMode = true
		return nil
	}
}

// WithLimitCgroup use cgroup to limit cpu and mem, param cpu's unit is cpu core num , mem's unit is MB
func WithLimitCgroup(cpu float64, mem int) optionFunc {
	return func(o *Netflow) error {
		o.cpuCore = cpu
		o.memMB = mem
		return nil
	}
}

func WithStorePcap(fpath string) optionFunc {
	return func(o *Netflow) error {
		o.pcapFileName = fpath
		return nil
	}
}

func WithCaptureTimeout(dur time.Duration) optionFunc {
	// capture name
	if dur > defaultCaptureTimeout {
		dur = defaultCaptureTimeout
	}

	return func(o *Netflow) error {
		o.captureTimeout = dur
		return nil
	}
}

func WithSyncInterval(dur time.Duration) optionFunc {
	return func(o *Netflow) error {
		if dur <= 0 {
			return errors.New("invalid sync interval")
		}

		o.syncInterval = dur
		return nil
	}
}

func WithWorkerNum(num int) optionFunc {
	if num <= 0 {
		num = defaultWorkerNum // default
	}

	return func(o *Netflow) error {
		o.workerNum = num
		return nil
	}
}

func WithCtx(ctx context.Context) optionFunc {
	return func(o *Netflow) error {
		cctx, cancel := context.WithCancel(ctx)
		o.ctx = cctx
		o.cancel = cancel
		return nil
	}
}

func WithBindIPs(ips []string) optionFunc {
	return func(o *Netflow) error {
		if len(ips) == 0 {
			return errors.New("invalid ips")
		}

		mm := make(map[string]nullObject, 10)
		for _, ip := range ips {
			mm[ip] = nullObject{}
		}

		o.bindIPs = mm
		return nil
	}
}

func WithBindDevices(devs []string) optionFunc {
	return func(o *Netflow) error {
		if len(devs) == 0 {
			return errors.New("invalid devs")
		}

		mm := make(map[string]nullObject, 6)
		for _, dev := range devs {
			mm[dev] = nullObject{}
		}

		o.bindDevices = mm
		return nil
	}
}

func WithQueueSize(size int) optionFunc {
	if size < 1000 {
		size = defaultQueueSize
	}

	return func(o *Netflow) error {
		o.qsize = size
		return nil
	}
}

const (
	defaultQueueSize      = 2000000 // 2w
	defaultWorkerNum      = 1       // usually one worker is enough.
	defaultSyncInterval   = time.Duration(1 * time.Second)
	defaultCaptureNum     = 1                                                //抓包持续时间
	defaultCaptureTimeout = time.Duration(1*time.Second) * defaultCaptureNum //抓包持续时间
)

type NetflowInterface interface {
	// start netflow
	Start() error

	// stop netflow
	Stop()

	// sum packet
	LoadCounter() int64

	// when ctx.cancel() or timeout, notify done.
	Done() <-chan struct{}
	GetProcess(pid int, recentSeconds int) (*Process, error) // 获取指定进程的流量等信息
}

func NewNetflow(opts ...optionFunc) (NetflowInterface, error) {
	var (
		ctx, cancel = context.WithCancel(context.Background())
	)

	ips, devs := parseIpaddrsAndDevices() //获取服务器eth0 本机ip和设备

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
		debugMode:      false,
		logger:         &loggerflow{},
		pcapFileName:   "",
	}

	for _, opt := range opts {
		err := opt(nf)
		if err != nil {
			return nil, err
		}
	}

	nf.ProcessAddrMap = UpdateProcessAddr(nf.procKeywords) //netstat 更新进程/地址

	nf.packetQueue = make(chan gopacket.Packet, nf.qsize) //2w大小
	nf.delayQueue = make(chan *delayEntry, nf.qsize)      //2w大小
	nf.connInodeHash = NewMapping()                       // 空map
	nf.processHash = NewProcessController(nf.ctx)         //进程对象集合---对应网络数据
	nf.processHash.procKeywords = nf.procKeywords

	return nf, nil
}

func (nf *Netflow) Done() <-chan struct{} {
	return nf.ctx.Done()
}

// 获取进程数据,参数10,3
func (nf *Netflow) GetProcessRank(limit int, recentSeconds int) ([]*Process, error) {
	if recentSeconds > maxRingSize {
		return nil, errors.New("[error] windows interval must <= 15")
	}

	nf.processHash.Sort(recentSeconds)
	prank := nf.processHash.GetRank(limit)
	return prank, nil
}

// 获取进程网络数据,参数pid,3
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

func (nf *Netflow) incrCounter() {
	atomic.AddInt64(&nf.counter, 1)
}

func (nf *Netflow) LoadCounter() int64 {
	return atomic.LoadInt64(&nf.counter)
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

func (nf *Netflow) configurePersist() error {
	if len(nf.pcapFileName) == 0 {
		return nil
	}

	f, err := os.Create(nf.pcapFileName)
	if err != nil {
		nf.logError("创建文件失败", err)
		return err
	}

	nf.pcapFile = f
	nf.pcapWriter = pcapgo.NewWriter(f)
	nf.pcapWriter.WriteFileHeader(1024, layers.LinkTypeEthernet)
	return nil
}

// 装填数据
func (nf *Netflow) Start() error {
	var err error
	err = nf.configurePersist() //抓包存文件
	if err != nil {
		nf.logError("创建抓包文件失败", err)
		return err
	}

	// linux cpu/mem by cgroup
	err = nf.configureCgroups()
	if err != nil {
		return err
	}

	// start workers
	nf.rescanResouce()
	go nf.startNetworkSniffer() //shumei:抓取数据包,整理好,放入队列,消费队列
	go nf.startResourceSyncer() //shumei:统计数据,进程信息,网络连接信息   消费抓到的数据包

	return nil
}

func (nf *Netflow) Stop() {
	nf.logDebug("stop 取消抓包")
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
					nf.logError("only hanlde entry before rescan")
					break
				}

				err := nf.handleDelayEntry(entry) //处理未匹配进程的数据包,处理失败则再处理一次,再次失败则放弃
				if err != nil {
					// time.Sleep(time.Second * 1)
					// nf.logDebug("[error]处理延迟数据包失败", entry.addr, entry.length)
					nf.rescanResouce()
					err = nf.handleDelayEntry(entry)
					if err != nil {
						nf.logDebug("[error]处理延迟数据包失败", entry.addr, entry.length)
					}
				} else {
					nf.logDebug("处理延迟数据包成功", entry.addr, entry.length)
				}

				entry = nil
			}
		}
	}
}

func (nf *Netflow) rescanResouce() error {
	// 核心方法,抓包前调用
	var wg errgroup.Group

	wg.Go(func() error {
		return nf.rescanConns() //读取/proc/net/tcp文件,关联地址和socketid  //connInodeHash  Inode <-> addr
	})
	wg.Go(func() error {
		return nf.rescanProcessInodes() //获取进程对应的所有socket-id,及进程基础信息 //inodePidMap Inode <-> pid
	})

	return wg.Wait()
}

func (nf *Netflow) rescanProcessInodes() error {
	return nf.processHash.Rescan()
}

func (nf *Netflow) rescanConns() error {
	conns, err := netstat("tcp") //读取/proc/net/tcp
	if err != nil {
		nf.logError("读取/proc/net/tcp失败", err)
		return err
	}
	//key是地址,value是socket-id
	for _, conn := range conns {
		// fmt.Println(conn.Addr, conn.Inode)
		nf.connInodeHash.Add(conn.Addr, conn.Inode)
		nf.connInodeHash.Add(conn.ReverseAddr, conn.Inode)
	}

	conns, err = netstat("tcp6") //读取/proc/net/tcp6
	if err != nil {
		nf.logError("读取/proc/net/tcp6失败", err)
		return err
	}
	//key是地址,value是socket-id
	for _, conn := range conns {
		nf.connInodeHash.Add(conn.Addr, conn.Inode)
		nf.connInodeHash.Add(conn.ReverseAddr, conn.Inode)
	}
	nf.logDebug("/proc/net/tcp扫描完成")
	return nil
}

func (nf *Netflow) captureDevice(dev string) {
	handler, err := buildPcapHandler(dev, nf.captureTimeout, nf.pcapFilter)
	if err != nil {
		return
	}

	defer func() {
		handler.Close()
	}()

	packetSource := gopacket.NewPacketSource( //创建数据包源
		handler,
		handler.LinkType(), //handle.LinkType() 此参数默认是以太网链路,即2层网络抓包
	)

	// 设置抓取包的数量
	var count int64 = 0
	for {
		select {
		case <-nf.ctx.Done(): //没问题
			nf.logDebug(fmt.Sprintf("captureDevice: %s, ctx.Done", dev))
			return

		case pkt := <-packetSource.Packets(): //此处是从channel类型的数据通道中持续的读取网络数据包
			nf.enqueue(pkt) // 队列满了就等待吧
			count += 1
			if count > defaultQueueSize {
				nf.logDebug(fmt.Sprintf("captureDevice count: %d, 超过defaultQueueSize退出抓包", defaultQueueSize))
				return
			}
		}
	}
}

func (nf *Netflow) enqueue(pkt gopacket.Packet) { //外层还有个循环一直取包.如果队列满了则丢弃不处理这个包
	select {
	case nf.packetQueue <- pkt: //写入包队列
		nf.incrCounter()
		return
	default:
		nf.logError("queue overflow, current size: ", len(nf.packetQueue))
	}
	// nf.packetQueue <- pkt
	// nf.incrCounter()
}

func (nf *Netflow) dequeue() gopacket.Packet {
	select {
	case pkt := <-nf.packetQueue: //取出数据包
		return pkt //返回数据包

	case <-nf.ctx.Done(): //没问题
		return nil
	}
}

func (nf *Netflow) loopHandlePacket() {
	for {
		pkt := nf.dequeue() //取一个包处理
		if pkt == nil {
			nf.logDebug(fmt.Sprintf("%s %s % s", "loopHandlePacket: ", "pkt is nil", "[数据包处理完]"))
			return // ctx.Done
		}

		nf.handlePacket(pkt)
	}
}

// 抓包获取包大小
func (nf *Netflow) handlePacket(packet gopacket.Packet) {
	// var (
	// 	ethLayer layers.Ethernet
	// 	ipLayer  layers.IPv4
	// 	tcpLayer layers.TCP

	// 	layerTypes = []gopacket.LayerType{}
	// )

	// parser := gopacket.NewDecodingLayerParser(
	// 	layers.LayerTypeEthernet,
	// 	&ethLayer,
	// 	&ipLayer,
	// 	&tcpLayer,
	// )

	// err := parser.DecodeLayers(packet.Data(), &layerTypes)
	// if err != nil {
	// 	continue
	// }

	// get ipLayer
	_ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if _ipLayer == nil {
		return
	}
	ipLayer, _ := _ipLayer.(*layers.IPv4)

	// get tcpLayer
	_tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if _tcpLayer == nil {
		return
	}
	tcpLayer, _ := _tcpLayer.(*layers.TCP)

	var (
		side sideOption

		localIP   = ipLayer.SrcIP
		localPort = tcpLayer.SrcPort

		remoteIP   = ipLayer.DstIP
		remotePort = tcpLayer.DstPort
	)

	if nf.isBindIPs(ipLayer.SrcIP.String()) { // 判断出入流量
		side = outputSide // 输出流量
	} else {
		side = inputSide //输入流量
	}

	length := len(packet.Data())            // ip header + tcp header + tcp payload
	length_payload := len(tcpLayer.Payload) //数据包长度
	addr := spliceAddr(localIP, localPort, remoteIP, remotePort)

	if length_payload != 0 {
		nf.increaseTraffic(addr, int64(length), side) //将包信息,长度,地址端口,添加到队列中等待处理,tag:这里可以拆分流量
	}

	if nf.pcapFile != nil {
		nf.pcapWriter.WritePacket(packet.Metadata().CaptureInfo, packet.Data()) //数据包写入本地文件
	}

	// fmt.Println(">>>>", addr, len(packet.Data()), len(tcpLayer.Payload), side)
}

func (nf *Netflow) logDebug(msg ...interface{}) {
	if !nf.debugMode {
		return
	}
	// 获取当前时间
	now := time.Now().Format(time.RFC3339)
	msg = append([]interface{}{now}, msg...)

	nf.logger.Debug(msg...)
}

func (nf *Netflow) logError(msg ...interface{}) {
	if !nf.debugMode {
		return
	}
	// 获取当前时间
	now := time.Now().Format(time.RFC3339)
	msg = append([]interface{}{now}, msg...)
	nf.logger.Error(msg...)
}

func (nf *Netflow) isBindIPs(ipa string) bool {
	_, ok := nf.bindIPs[ipa]
	return ok
}

func (nf *Netflow) startNetworkSniffer() {
	// time.Sleep(time.Millisecond * 100) //等待同步socketip
	nf.logDebug("开始抓包")
	for dev := range nf.bindDevices { //eth0
		go nf.captureDevice(dev) //抓包,放入队列
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

type delayEntry struct {
	// meta
	timestamp time.Time
	times     int

	// data
	addr   string
	length int64
	side   sideOption
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

// 根据数据包大小对应的地址,找到进程
func (nf *Netflow) handleDelayEntry(entry *delayEntry) error {
	proc, err := nf.getProcessByAddr(entry.addr) //通过数据包地址获取进程id
	if err != nil {
		return err
	}

	nf.increaseProcessTraffic(proc, entry.length, entry.side, entry.addr) //为进程添加包大小
	return nil
}

func (nf *Netflow) getProcessByAddr(addr string) (*Process, error) {
	inode := nf.connInodeHash.Get(addr) //通过地址获取socketid,有很多外部访问本地端口的短连接获取不到socketid,说明连接很短,没有socketid
	if len(inode) == 0 {
		// not found, to rescan

		// 获取本机ip地址
		// var addr string
		// for ip,_ := range nf.bindIPs{
		// 	addr=ip
		// }
		// 获取本机监听端口
		// processAddr := UpdateProcessAddr(nf.procKeywords)
		processAddr := nf.ProcessAddrMap
		for addrport, pid := range processAddr {
			if strings.Contains(addr, addrport) {
				// fmt.Println("根据addrport数据找进程", addrport, pid)
				pid_str := fmt.Sprintf("%d", pid)
				proc := nf.processHash.Get(pid_str)
				return proc, nil
			}
		}
		// nf.logDebug("not found socketid ", addr)
		return nil, errNotFound
	}

	proc := nf.processHash.GetProcessByInode(inode) //通过socketid,获取进程,有socketid一般都能找到进程,除非不是进程的socketid,说明socketid都拿到了
	if proc == nil {
		// not found, to rescan
		// nf.logDebug("not found proc ", addr)
		return nil, errProcNotFound //找到socketid,没找到进程就不放入延迟队列了
	}

	return proc, nil
}

// 给进程增加包大小长度
func (nf *Netflow) increaseProcessTraffic(proc *Process, length int64, side sideOption, addr string) error {
	// 处理延迟和实时数据包都是这个函数
	switch side {
	case inputSide:
		proc.IncreaseInput(length, addr, nf.ServiceAddr, nf.IsAllConn, nf.IsRecordPublic) //统计指定服务带宽,是否统计所有连接流量
	case outputSide:
		proc.IncreaseOutput(length, addr, nf.ServiceAddr, nf.IsAllConn, nf.IsRecordPublic)
	}
	return nil
}

// 将处理好的数据包数据放到delay队列处理
func (nf *Netflow) increaseTraffic(addr string, length int64, side sideOption) error {
	// 这里可以拆分流量,有进程,有地址
	proc, err := nf.getProcessByAddr(addr)

	if err != nil {
		if err == errProcNotFound {
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

type nullObject = struct{}

func parseIpaddrsAndDevices() (map[string]nullObject, map[string]nullObject) {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return nil, nil
	}

	var (
		bindIPs  = map[string]nullObject{}
		devNames = map[string]nullObject{}
	)

	for _, dev := range devs {
		for _, addr := range dev.Addresses {
			if addr.IP.IsMulticast() {
				continue
			}
			bindIPs[addr.IP.String()] = struct{}{}
		}

		if strings.HasPrefix(dev.Name, "eth") {
			devNames[dev.Name] = nullObject{}
			continue
		}

		// if strings.HasPrefix(dev.Name, "em") {
		// 	devNames[dev.Name] = nullObject{}
		// 	continue
		// }

		// if strings.HasPrefix(dev.Name, "lo") {
		// 	devNames[dev.Name] = nullObject{}
		// 	continue
		// }

		// if strings.HasPrefix(dev.Name, "bond") {
		// 	devNames[dev.Name] = nullObject{}
		// 	continue
		// }
	}
	return bindIPs, devNames
}

// 构建gopacket 包handle
func buildPcapHandler(device string, timeout time.Duration, pfilter string) (*pcap.Handle, error) {
	var (
		snapshotLen int32 = 65536
		promisc     bool  = false
	)

	// if packet captured size >= snapshotLength or 1 second's timer is expired, call user layer.
	// 实时捕获数据包,device:网络设备的名称,snaplen: 每个数据包读取的最大长度,promisc:是否将网口设置为混杂模式,timeout:设置抓到包返回的超时
	handler, err := pcap.OpenLive(device, snapshotLen, promisc, time.Second)
	if err != nil {
		return nil, err
	}

	var filter = "tcp and (not broadcast and not multicast) and not port 22"
	if len(pfilter) != 0 {
		filter = fmt.Sprintf("%s and %s", filter, pfilter)
	}

	err = handler.SetBPFFilter(filter) //添加过滤规则
	if err != nil {
		return nil, err
	}

	return handler, nil
}

func spliceAddr(sip net.IP, sport layers.TCPPort, dip net.IP, dport layers.TCPPort) string {
	return fmt.Sprintf("%s:%d_%s:%d", sip, sport, dip, dport)
}
