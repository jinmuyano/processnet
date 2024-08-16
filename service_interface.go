package pnet

type BandWidth struct {
	InRate     int64            // 进程入带宽
	OutRate    int64            // 进程出带宽
	InService  map[string]int64 //指定统计的服务入带宽,如果public为true,则会公网入带宽会被统计到
	OutService map[string]int64 //指定统计的服务出带宽,如果public为true,则会公网出带宽会被统计到
	Cmdline    string           // 进程命令行
}

type Result map[int]BandWidth //key为进程pid

type ClientInterface interface {
	Start()               // 启动抓包.并开启定时任务,定时更新流量统计结果
	Stop()                // 关闭定时任务
	Run() Result          // 启动抓包获取流量统计结果返回,及进程信息
	GetBandWidth() Result // 获取流量统计结果
}
