package cni0

import (
	"fmt"

	"github.com/jinmuyano/processnet"
	"github.com/robfig/cron"
)

type BandWidth struct {
	InRate     int64
	OutRate    int64
	InService  map[string]int64
	OutService map[string]int64
}

type Result map[int]BandWidth

type CniPacketClient struct {
	conf    PacketClientConfig
	Result  pnet.Result
	crontab *cron.Cron
}

type PacketClientConfig struct {
	//抓取频率,默认10s
	Interval         string            //10s,1m,1h
	IsRecordPublic   bool              //是否统计公网流量
	ServiceConfigUrl string            //解析指定ip地址,比如指定zk,mysql,redis访问的ip地址,某个项目的所有ip端口
	ProcessKeyword   []string          //抓取的进程关键词,默认java
	ServiceAddr      map[string]string //解析指定ip地址,比如指定zk,mysql,redis访问的ip地址,某个项目的所有ip端口
	IsAllConn        bool              //是否统计所有连接
}

func NewPacketClientConfig() PacketClientConfig {
	return PacketClientConfig{
		Interval:         "60s",
		IsRecordPublic:   true,
		ServiceConfigUrl: "",
		ProcessKeyword:   []string{"java","python3"},
		IsAllConn:        false,
		// ServiceAddr: map[string]string{
		// 	"192.168.165.xx:30002":  "zk-bak",
		// 	"192.168.162.1xx:30002": "zk-erp",
		// 	"192.168.162.1xx:30003": "zk-ec",
		// },
	}
}

func (c *CniPacketClient) Start() {
	fmt.Println("cni0 capture start")
	c.run() //启动+更新数据+分析带宽+结束
	// c.newcron()
}

func (c *CniPacketClient) Run() pnet.Result {
	fmt.Println("cni0 capture start")
	c.run() //启动+更新数据+分析带宽+结束
	result := c.GetBandWidth()
	return result
}

func (c *CniPacketClient) Stop() {
	fmt.Println("stop exit")
	c.crontab.Stop()
}

func (c *CniPacketClient) setBandWidth(data pnet.Result) {
	fmt.Println("更新")
	c.Result = data
}

func (c *CniPacketClient) GetBandWidth() pnet.Result {
	return c.Result
}

func (c *CniPacketClient) run() {
	// fmt.Println("cni0 capture start")
	netflowStart(c) //启动+更新数据+分析带宽+结束
}

func (c *CniPacketClient) newcron() {
	c.crontab = cron.New()
	timeInterval := fmt.Sprintf("@every %s", c.conf.Interval)
	fmt.Println("定时任务时间", timeInterval)
	c.crontab.AddFunc(timeInterval, c.run)
	c.crontab.Start()
}

func NewPacketClient(conf PacketClientConfig) pnet.ClientInterface {
	fmt.Println("new packet client")
	return &CniPacketClient{
		conf: conf,
	}
}
