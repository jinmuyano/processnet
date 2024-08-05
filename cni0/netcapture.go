package cni0

import (
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func (nf *Netflow) captureDevice(dev string) {
	/*
		实时获取数据包
	*/
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
			log.Println(fmt.Sprintf("captureDevice: %s, ctx.Done", dev))
			return

		case pkt := <-packetSource.Packets(): //此处是从channel类型的数据通道中持续的读取网络数据包
			nf.enqueue(pkt) // 队列满了就等待吧
			count += 1
			if count > defaultQueueSize {
				log.Println(fmt.Sprintf("captureDevice count: %d, 超过defaultQueueSize退出抓包", defaultQueueSize))
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
		log.Println("queue overflow, current size: ", len(nf.packetQueue))
	}
	// nf.packetQueue <- pkt
	// nf.incrCounter()
}

func (nf *Netflow) incrCounter() {
	atomic.AddInt64(&nf.counter, 1)
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
			log.Println(fmt.Sprintf("%s %s % s", "loopHandlePacket: ", "pkt is nil", "[数据包处理完]"))
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
			if strings.Contains(dev.Name, "cni") {
				bindIPs[addr.IP.String()] = struct{}{}
			}
		}

		if strings.HasPrefix(dev.Name, "cni") || strings.HasPrefix(dev.Name, "cali") {
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
