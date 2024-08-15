# 实现
1.读取/proc/pid/fd/socket文件,关联pid和socket_id
2.读取/proc/net/tcp,根据socket_id记录ip和port
3.读取/proc/net/tcp6,根据socket_id记录ip和port
4.读取netstat -lnputa,根据ip和port记录pid



# 目录
- interface.go 调用接口

- netflow_init.go
  - 启动关闭netflow

- netflow_process.go
  - IncreaseInput 统计进程下,不同服务流量大小
  - GetProcesses 获取/proc下对应进程对象
  - analyseStats 汇总进程流量
  - 进程控制器创建


- netflow_procnet.go
  - parseNetworkLines 解析tcp文件
  - 转换ip

- netflow.go
  - 抓包,解析出入流量

- process.go
  - 一些帮助方法