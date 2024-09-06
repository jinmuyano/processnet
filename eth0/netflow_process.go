package eth0

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	maxRingSize = 15
)

type Process struct {
	Name         string             `json:"name"`
	Pid          string             `json:"pid"`
	Exe          string             `json:"exe"`
	Cmdline      string             `json:"cmdline"` // 进程命令行参数
	State        string             `json:"state"`
	InodeCount   int                `json:"inode_count"`
	TrafficStats *trafficStatsEntry `json:"traffic_stats"`

	// todo: use ringbuffer array to reduce gc cost.
	Ring          []*trafficEntry  `json:"ring"` //包大小数据队列
	InServiceNet  map[string]int64 `json:"in_service_net"`
	OutServiceNet map[string]int64 `json:"out_service_net"`
	inodes        []string
	revision      int
}

func (p *Process) getLastTrafficEntry() *trafficEntry {
	if len(p.Ring) == 0 {
		return nil
	}
	return p.Ring[len(p.Ring)-1]
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

// 收缩
func (po *Process) shrink() {
	if len(po.Ring) >= maxRingSize {
		po.Ring = po.Ring[1:] // reduce size
	}
}

/*
1.判断是否公网ip
*/
func IsPublicIp(ip string) bool {
	var publicIp = []string{"192.168", "10.", "172.", "100.118"}
	for _, ip := range publicIp {
		if strings.HasPrefix(ip, ip) {
			return false
		}
	}
	return true //是公网

}

/*
1.统计输入流量
*/
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
			if IsPublicIp(localAddr) {
				//来源于外网
				// fmt.Println("public addrList", addrList)
				po.InServiceNet["public|"+localAddr] += n
			}
			if IsPublicIp(remoteAddr) {
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
			if IsPublicIp(localAddr) {
				//来源于外网
				// fmt.Println("public addrList", addrList)
				po.OutServiceNet["public|"+localAddr] += n
			}
			if IsPublicIp(remoteAddr) {
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

func (p *Process) copy() *Process {
	return &Process{
		Name:       p.Name,
		Pid:        p.Pid,
		Exe:        p.Exe,
		State:      p.State,
		InodeCount: p.InodeCount,
		TrafficStats: &trafficStatsEntry{
			In:      p.TrafficStats.In,
			Out:     p.TrafficStats.Out,
			InRate:  p.TrafficStats.InRate,
			OutRate: p.TrafficStats.OutRate,
		},
		Ring: p.Ring,
	}
}

type trafficEntry struct {
	Timestamp int64 `json:"timestamp"`
	In        int64 `json:"in"`
	Out       int64 `json:"out"`
}

type trafficStatsEntry struct {
	In         int64            `json:"in"`
	Out        int64            `json:"out"`
	InRate     int64            `json:"in_rate"`
	OutRate    int64            `json:"out_rate"`
	InputEWMA  int64            `json:"input_ewma" valid:"-"`
	OutputEWMA int64            `json:"output_ewma" valid:"-"`
	InService  map[string]int64 `json:"in_service_net"`
	OutService map[string]int64 `json:"out_service_net"`
}

func GetProcesses(prockeywords []string) (map[string]*Process, error) {
	// 整理进程inode列表
	// to improve performance
	files, err := filepath.Glob("/proc/[0-9]*/fd/[0-9]*")
	if err != nil {
		return nil, err
	}

	var (
		ppm   = make(map[string]*Process, 1000)
		label = "socket:["
	)

	// shumei:这里要加过滤逻辑,过滤进程
	for _, fpath := range files {
		rules := []string{"fd/0", "fd/1", "fd/2"} //这些文件过滤掉
		if matchStringSuffix(fpath, rules) {
			continue
		}

		name, _ := os.Readlink(fpath) //获取软连接的目标地址

		if !strings.HasPrefix(name, label) {
			continue
		}

		var (
			pid   = strings.Split(fpath, "/")[2]
			inode = name[len(label) : len(name)-1] //socket-id
		)
		exe := getProcessExe(pid)
		// shumei add  只归集进程对应的socket文件
		// fmt.Println("exe 信息:", exe)

		isMatch := isMatchProcess(exe, prockeywords)
		if !isMatch {
			continue
		}

		po := ppm[pid] // 归集进程对应的socket-id
		if po != nil { // has
			po.inodes = append(po.inodes, inode)
			po.InodeCount = len(po.inodes)
			continue
		}

		//执行完整路径
		pname := getProcessName(exe)

		// 获取进程命令行
		cmdline := getcmdlineProject(pid)
		// 初始化网络对应的进程对象
		ppm[pid] = &Process{
			Pid:           pid,
			inodes:        []string{inode}, //socket-id列表
			InodeCount:    1,
			Name:          pname, //执行完整路径--->java
			Cmdline:       cmdline,
			Exe:           exe, //exe -> /usr/local/jdk1.8.0_112/bin/java
			TrafficStats:  new(trafficStatsEntry),
			InServiceNet:  map[string]int64{}, // increase包时使用
			OutServiceNet: map[string]int64{},
		}
	}
	// fmt.Println("归集pid socketid完成")
	return ppm, nil
}

type processController struct {
	sync.RWMutex

	ctx    context.Context
	cancel context.CancelFunc

	// key -> pid, val -> process
	dict     map[string]*Process
	revision int

	// key -> inode_num, val -> pid_num
	inodePidMap map[string]string

	// cache
	sortedProcesses sortedProcesses

	procKeywords []string
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
		inodePidMap: make(map[string]string, size),
	}
}

func (pm *processController) GetRank(limit int) []*Process {
	pm.RLock()
	defer pm.RUnlock()

	src := pm.sortedProcesses
	if len(src) > limit {
		src = pm.sortedProcesses[:limit]
	}

	// copy object
	res := []*Process{}
	for _, item := range src {
		res = append(res, item.copy())
	}
	return src
}

func (pm *processController) Sort(sec int) []*Process {
	pm.RLock()
	defer pm.RUnlock()

	pos := sortedProcesses{}
	for _, po := range pm.dict {
		po.analyseStats(sec)
		pos = append(pos, po)
	}

	sort.Sort(pos)
	pm.sortedProcesses = pos

	return pos
}

// shumei:添加获取某个进程带宽
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

func (pm *processController) Add(pid string, p *Process) {
	pm.Lock()
	defer pm.Unlock()

	pm.dict[pid] = p
}

func (pm *processController) Get(pid string) *Process {
	pm.RLock()
	defer pm.RUnlock()
	p, ok := pm.dict[pid]
	if !ok {
		fmt.Println(pid, "pm.dict[pid] 不存在")
		return nil
	}
	return p
}
func (pm *processController) GetProcessByPid(pid string) *Process {
	pm.RLock()
	defer pm.RUnlock()

	return pm.dict[pid]
}

func (pm *processController) GetProcessByInode(inode string) *Process {
	pm.RLock()
	defer pm.RUnlock()

	pid, ok := pm.inodePidMap[inode]
	if !ok {
		return nil
	}

	return pm.dict[pid]
}

func (pm *processController) delete(pid string) {
	pm.Lock()
	defer pm.Unlock()

	delete(pm.dict, pid)
}

func (pm *processController) readIterator(fn func(*Process)) {
	pm.RLock()
	defer pm.RUnlock()

	for _, po := range pm.dict {
		fn(po)
	}
}

func (pm *processController) anyIterator(fn func(*Process)) {
	pm.Lock()
	defer pm.Unlock()

	for _, po := range pm.dict {
		fn(po)
	}
}

func (pm *processController) copy() map[string]*Process {
	ndict := make(map[string]*Process, len(pm.dict))

	pm.RLock()
	defer pm.RUnlock()

	for k, v := range pm.dict {
		ndict[k] = v
	}
	return ndict
}

func (pm *processController) AsyncRun() {
	go pm.Run()
}

func (pm *processController) Run() {
	var (
		interval = 5 * time.Second
		ticker   = time.NewTicker(interval)
	)

	pm.Rescan()

	for {
		select {
		case <-pm.ctx.Done():
			return

		case <-ticker.C:
			pm.Rescan()
		}
	}
}

func (pm *processController) Stop() {
	pm.cancel()
}

func (pm *processController) sortNetflow() string {
	bs, _ := json.MarshalIndent(pm.dict, "", "    ")
	return string(bs)
}

func (pm *processController) analyse() error {
	pm.RLock()
	defer pm.RUnlock()

	for pid, po := range pm.dict {
		fmt.Println(pid, po)
	}

	return nil
}

func (pm *processController) Rescan() error {
	ps, err := GetProcesses(pm.procKeywords) //获取进程基础信息,及对应的所有socket-id
	if err != nil {
		return err
	}

	pm.Lock()
	defer pm.Unlock()

	pm.revision++

	// add new pid
	for pid, po := range ps {
		pp, ok := pm.dict[pid]
		if ok {
			pp.inodes = po.inodes
			continue // alread exist
		}

		pm.dict[pid] = po
	}

	// del old pid
	for pid := range pm.dict {
		_, ok := ps[pid]
		if ok {
			continue
		}

		delete(pm.dict, pid)
	}

	// inode -> pid
	inodePidMap := make(map[string]string, 1000)
	for pid, po := range ps {
		for _, inode := range po.inodes {
			inodePidMap[inode] = pid
		}
	}
	pm.inodePidMap = inodePidMap // obj reset

	return nil
}

func (pm *processController) Reset() {
	pm.dict = make(map[string]*Process, 1000)
	pm.inodePidMap = make(map[string]string, 1000)
}

/*
1.执行路径:exe -> /usr/local/jdk1.8.0_112/bin/java
*/
func getProcessExe(pid string) string {
	exe := fmt.Sprintf("/proc/%s/exe", pid)
	path, _ := os.Readlink(exe)
	return path
}

// getProcessName
func getProcessName(exe string) string {
	n := strings.Split(exe, "/")
	name := n[len(n)-1]
	return strings.Title(name)
}

/*
1.根据cmdline文件获取项目名称
*/

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

// findPid unuse
func findPid(inode string) string {
	pid := "-"

	d, err := filepath.Glob("/proc/[0-9]*/fd/[0-9]*")
	if err != nil {
		fmt.Println("[error]", err)
		os.Exit(1)
	}

	re := regexp.MustCompile(inode)
	for _, item := range d {
		path, _ := os.Readlink(item)
		out := re.FindString(path)
		if len(out) != 0 {
			pid = strings.Split(item, "/")[2]
		}
	}
	return pid
}

type sortedProcesses []*Process

func (s sortedProcesses) Len() int {
	return len(s)
}

func (s sortedProcesses) Less(i, j int) bool {
	val1 := s[i].TrafficStats.In + s[i].TrafficStats.Out
	val2 := s[j].TrafficStats.In + s[j].TrafficStats.Out
	return val1 > val2
}

func (s sortedProcesses) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}
