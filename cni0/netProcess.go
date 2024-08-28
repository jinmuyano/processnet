package cni0

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

var (
	maxRingSize = 15
)

// 归集网络数据到进程
type trafficStatsEntry struct {
	In         int64            `json:"in"`
	Out        int64            `json:"out"`
	InRate     int64            `json:"in_rate"`
	OutRate    int64            `json:"out_rate"`
	InService  map[string]int64 `json:"in_service_net"` //服务带宽
	OutService map[string]int64 `json:"out_service_net"`
}

type trafficEntry struct {
	Timestamp int64 `json:"timestamp"` //归集数据包到某秒
	In        int64 `json:"in"`
	Out       int64 `json:"out"`
}

type Process struct {
	Name    string `json:"name"`
	Pid     string `json:"pid"`
	Exe     string `json:"exe"`
	State   string `json:"state"`
	Cmdline string `json:"cmdline"`
	// InodeCount   int                `json:"inode_count"`
	Addr         string             `json:"addr"`
	TrafficStats *trafficStatsEntry `json:"traffic_stats"`

	// todo: use ringbuffer array to reduce gc cost.
	Ring          []*trafficEntry  `json:"ring"` //汇总数据包大小
	InServiceNet  map[string]int64 `json:"in_service_net"`
	OutServiceNet map[string]int64 `json:"out_service_net"`
	// inodes        []string
	revision int
}

type processController struct {
	sync.RWMutex

	ctx    context.Context
	cancel context.CancelFunc

	// key -> pid, val -> process   | new : addr-->process
	dict        map[string]*Process
	dictAddrPid map[string]string // key -> addr, val -> pid
	revision    int

	// cache

	procKeywords []string
}

func (pm *processController) getProcessByAddrPort(addrPort string) *Process {
	pm.RLock()
	defer pm.RUnlock()
	var getpid string
	for addr, pid := range pm.dictAddrPid {
		if strings.Contains(addrPort, addr) {
			getpid = pid
			break
		}
	}

	proc, ok := pm.dict[getpid]
	if !ok {
		return nil
	}

	return proc
}

func (pm *processController) GetProcess(pid int, sec int) *Process {
	pm.RLock()
	defer pm.RUnlock()
	str := fmt.Sprintf("%d", pid)
	proc := pm.Get(str)
	if proc == nil {
		fmt.Println("proc is nil")
		return nil
		// panic("proc is nil")
	}
	proc.analyseStats(sec)

	return proc
}

func (pm *processController) Get(pid string) *Process {
	pm.RLock()
	defer pm.RUnlock()
	p, ok := pm.dict[pid]
	if !ok {
		fmt.Println(pid, "pm.dict[addr] 不存在")
		return nil
	}
	return p
}

func (pm *processController) GetProcessByPid(pid string) *Process {
	pm.RLock()
	defer pm.RUnlock()

	return pm.dict[pid]
}

func (pm *processController) Add(pid string, p *Process) {
	pm.Lock()
	defer pm.Unlock()

	pm.dict[pid] = p
}

func matchStringSuffix(s string, mv []string) bool {
	for _, val := range mv {
		if strings.HasSuffix(s, val) {
			return true
		}
	}
	return false
}

func getProcessExe(pid string) string {
	exe := fmt.Sprintf("/proc/%s/exe", pid)
	path, _ := os.Readlink(exe)
	return path
}

func getProcessName(exe string) string {
	n := strings.Split(exe, "/")
	name := n[len(n)-1]
	return strings.Title(name)
}

func getcmdlineProject(pid string) string {

	cmdlinefile := fmt.Sprintf("/proc/%s/cmdline", pid)
	// 读取io
	content, err := ioutil.ReadFile(cmdlinefile)
	if err != nil {
		return ""
	}
	cmdline := string(content)

	// 将所有的\x00替换成空格
	cmdLineWithSpaces := strings.ReplaceAll(cmdline, "\x00", " ")
	cmdLineWithSpaces = strings.Trim(cmdLineWithSpaces, " ")

	return cmdLineWithSpaces
}

func GetProcesses(prockeywords []string) (map[string]*Process, error) {
	// 整理进程inode列表
	// to improve performance
	// /proc/3949949/net/fib_trie
	files, err := filepath.Glob("/proc/[0-9]*/net/fib_trie")
	if err != nil {
		return nil, err
	}

	var (
		ppm = make(map[string]*Process, 1000)
	)

	// shumei:这里要加过滤逻辑,过滤进程
	for _, fpath := range files {
		var (
			pid = strings.Split(fpath, "/")[2]
		)
		exe := getProcessExe(pid)
		// shumei add  只归集进程对应的socket文件
		// fmt.Println("exe 信息:", exe)

		isMatch := isMatchProcess(exe, prockeywords)
		if !isMatch {
			continue
		}

		// 获取pid对应的addr
		var addr string
		// 读取文件内容
		content, err := ioutil.ReadFile(fpath)
		if err != nil {
			fmt.Println("read file error", fpath)
		}
		re := regexp.MustCompile(`(10\.\d+\.\d+\.\d+)\s+\/32 host LOCAL`)
		matches := re.FindAllStringSubmatch(string(content), 1)
		for _, match := range matches {
			if len(match) > 1 {
				// fmt.Printf("pid:%s,Container IP: %s\n", pid, match[1])
				addr = match[1]
				break
			}
		}

		if addr == "" {
			continue
		}
		//执行完整路径
		pname := getProcessName(exe) //=

		// 获取命令行参数
		cmdline := getcmdlineProject(pid)

		// 初始化网络对应的进程对象
		ppm[pid] = &Process{
			Pid:           pid,
			Name:          pname, //执行完整路径
			Exe:           exe,   //
			Addr:          addr,
			Cmdline:       cmdline,
			TrafficStats:  new(trafficStatsEntry),
			InServiceNet:  map[string]int64{}, // increase包时使用
			OutServiceNet: map[string]int64{},
		}

	}
	return ppm, nil
}

func (pm *processController) Rescan() error {
	// pid---process --->addr
	ps, err := GetProcesses(pm.procKeywords) //获取进程基础信息,及对应的所有socket-id
	if err != nil {
		return err
	}

	for addr, proc := range ps {
		fmt.Println("addr:", addr, "proc:", proc.Pid)
	}

	pm.Lock()
	defer pm.Unlock()

	pm.revision++

	// add new pid
	for pid, po := range ps {
		_, ok := pm.dict[pid]
		if ok {
			// 存在则跳过
			// pp.inodes = po.inodes
			// pp.Addr = addr
			continue // alread exist
		}

		pm.dict[pid] = po
		pm.dictAddrPid[po.Addr] = pid // obj reset

	}

	// del old pid
	for pid := range pm.dict {
		_, ok := ps[pid] // 刚获取的进程存在
		if ok {
			continue
		}

		delete(pm.dict, pid)
		if pm.dict[pid] == nil || pm.dictAddrPid == nil {
			continue
		}
		delete(pm.dictAddrPid, pm.dict[pid].Addr)
	}

	// inode -> pid

	return nil
}

func NewProcessController(ctx context.Context) *processController {
	var (
		size = 1000
	)

	cctx, cancel := context.WithCancel(ctx)
	return &processController{
		ctx:         cctx,
		cancel:      cancel,
		dict:        make(map[string]*Process, size),
		dictAddrPid: make(map[string]string, size),
	}
}

func isMatchProcess(exe string, keywords []string) bool {
	for _, key := range keywords {
		if strings.Contains(exe, key) {
			return true
		}
	}
	return false
}

func (po *Process) shrink() {
	if len(po.Ring) >= maxRingSize {
		po.Ring = po.Ring[1:] // reduce size
	}
}

func (po *Process) IncreaseInput(n int64, addr string, serviceAddr map[string]string, isAllConn bool, isRecordPublic bool) {
	// 统计进程外网流量
	for ipport, service := range serviceAddr {
		if strings.Contains(addr, ipport) {
			po.InServiceNet[service+"|"+ipport] += n
		}
	}

	addrList := strings.Split(addr, "_")
	if len(addrList) == 2 {
		localAddr := addrList[0]
		remoteAddr := addrList[1]
		if isRecordPublic {
			if !strings.HasPrefix(localAddr, "192.168") && !strings.HasPrefix(localAddr, "10.") {
				//来源于外网
				// fmt.Println("public addrList", addrList)
				po.InServiceNet["public|"+localAddr] += n
			}
			if !strings.HasPrefix(remoteAddr, "192.168") && !strings.HasPrefix(remoteAddr, "10.") {
				// fmt.Println("public addrList", addrList)
				//来源于外网
				po.InServiceNet["public|"+remoteAddr] += n
			}
		}
		if isAllConn {
			po.InServiceNet[localAddr] += n
		}
	}

	// 统计进程流程
	now := time.Now().Unix() // 如果抓包时间为3s,则有多个时间戳
	if len(po.Ring) == 0 {
		item := &trafficEntry{
			Timestamp: now,
			In:        n,
		}
		po.Ring = append(po.Ring, item)
		return
	}

	po.shrink()

	item := po.Ring[len(po.Ring)-1]
	if item.Timestamp == now {
		item.In += n //这里没有考虑这个包对应的地址是什么,只是按时间戳来累加大小,所以最后ring对列的数量很小
		return
	}

	item = &trafficEntry{
		Timestamp: now,
		In:        n,
	}
	po.Ring = append(po.Ring, item)
}

// IncreaseOutput
func (po *Process) IncreaseOutput(n int64, addr string, serviceAddr map[string]string, isAllConn bool, isRecordPublic bool) {
	// 统计外网流量
	for ipport, service := range serviceAddr {
		if strings.Contains(addr, ipport) {
			po.OutServiceNet[service+"|"+ipport] += n
		}
	}

	addrList := strings.Split(addr, "_")
	if len(addrList) == 2 {
		localAddr := addrList[0]
		remoteAddr := addrList[1]
		if isRecordPublic {
			if !strings.HasPrefix(localAddr, "192.168") && !strings.HasPrefix(localAddr, "10.") {
				//来源于外网
				// fmt.Println("public addrList", addrList)
				po.OutServiceNet["public|"+localAddr] += n
			}
			if !strings.HasPrefix(remoteAddr, "192.168") && !strings.HasPrefix(remoteAddr, "10.") {
				// fmt.Println("public addrList", addrList)
				//来源于外网
				po.OutServiceNet["public|"+remoteAddr] += n
			}
		}
		if isAllConn {
			po.OutServiceNet[remoteAddr] += n
		}
	}

	// 统计进程流量
	now := time.Now().Unix()
	if len(po.Ring) == 0 {
		item := &trafficEntry{
			Timestamp: now,
			Out:       n,
		}
		po.Ring = append(po.Ring, item)
		return
	}

	po.shrink()

	item := po.Ring[len(po.Ring)-1]
	if item.Timestamp == now {
		item.Out += n
		return
	}

	item = &trafficEntry{
		Timestamp: now,
		Out:       n,
	}
	po.Ring = append(po.Ring, item)
}

func (p *Process) analyseStats(sec int) {
	var (
		stats = new(trafficStatsEntry)
		// thold = time.Now().Add(-time.Duration(sec) * time.Second).Unix() //获取当前时间15s前的时间戳
	)
	stats.InService = map[string]int64{}
	stats.OutService = map[string]int64{}

	// avoid x / 0 to raise exception
	if sec == 0 {
		fmt.Println(sec, "is 0")
		return
	}

	for _, item := range p.Ring {
		// 15s前的数据不统计
		// if item.Timestamp < thold {
		// 	fmt.Println(item.Timestamp, "[error]no xxxx  thold", thold)
		// 	continue
		// }
		// fmt.Println("item.Timestamp", item.Timestamp, "thold", thold)
		stats.In += item.In
		stats.Out += item.Out

	}
	// p.InServiceNet是increase 包时统计的
	for svc, in := range p.InServiceNet {
		stats.InService[svc] = in * 8 / int64(sec)
	}

	for svc, out := range p.OutServiceNet {
		stats.OutService[svc] = out * 8 / int64(sec)
	}

	// fmt.Println("服务带宽", stats.InService, stats.OutService)
	stats.InRate = stats.In * 8 / int64(sec)
	stats.OutRate = stats.Out * 8 / int64(sec)
	p.TrafficStats = stats
}
