package eth0

import (
	"fmt"
	"github.com/mitchellh/go-ps"
	"os/exec"
	"regexp"
	"strings"

	"net"
)

func eth0Ip() string {
	interfaces, err := net.Interfaces()
	if err != nil {
		// fmt.Printf("Failed to get network interfaces: %s\n", err.Error())
		fmt.Println("Failed to get network interfaces:", err.Error())
	}

	for _, intf := range interfaces {
		if intf.Name == "eth0" {
			addrs, err := intf.Addrs()
			if err != nil {
				// fmt.Printf("Failed to get addresses for interface %s: %s\n", intf.Name, err.Error())
				fmt.Println("Failed to get addresses for interface", intf.Name, err.Error())
			}

			for _, addr := range addrs {
				ipNet, ok := addr.(*net.IPNet)
				if ok && !ipNet.IP.IsLoopback() && ipNet.IP.To4() != nil {
					return ipNet.IP.String()
				}
			}
		}
	}
	return ""
}

func isMatchProcess(exe string, keywords []string) bool {
	for _, key := range keywords {
		if strings.Contains(exe, key) {
			return true
		}
	}
	return false
}

func UpdateProcessAddr(procKeywords []string) map[string]int {
	/*
		netstat 数据
		更新进程监听的ip端口,分析抓包用,
	*/
	// 取进程监听端口号
	processes, err := ps.Processes()
	if err != nil {
		fmt.Println("cron readprocess [error]", err)
		return nil
	}

	var pidList []int // 当前进程id
	for _, p := range processes {
		// 过滤进程
		ismatch := isMatchProcess(p.Executable(), procKeywords)
		if ismatch {
			pid := p.Pid()
			pidList = append(pidList, pid)
		}
	}

	var addrportMap = make(map[string]int)

	ip := eth0Ip()
	for _, pid := range pidList {
		cmd_netstat := fmt.Sprintf("netstat -lnpt|grep %d/", pid)
		// fmt.Println(cmd_netstat)
		line := exec.Command("bash", "-c", cmd_netstat)
		output, err := line.CombinedOutput()
		if err != nil {
			fmt.Println("[error]", err)
		}
		// fmt.Println(string(output))
		re := regexp.MustCompile(`(tcp|tcp6)\s+[\d]+\s+[\d]+\s+[^\s]+:([0-9]+)\s+`)
		line_match := re.FindAllStringSubmatch(string(output), -1) //匹配全文,获取项目进程监听的端口号,分析流量使用
		for _, v := range line_match {
			ipport := fmt.Sprintf("%s:%s", ip, v[2])
			addrportMap[ipport] = pid
		}
	}
	return addrportMap
}
