package pnet

type BandWidth struct {
	InRate     int64            // 进程入带宽
	OutRate    int64            // 进程出带宽
	InService  map[string]int64 //指定统计的服务入带宽,如果public为true,则会公网入带宽会被统计到
	OutService map[string]int64 //指定统计的服务出带宽,如果public为true,则会公网出带宽会被统计到
}

type Result map[int]BandWidth //key为进程pid

type PacketClient interface {
	Start()               //启动抓包
	Stop()                //关闭退出抓包
	GetBandWidth() Result //获取流量统计结果
}
