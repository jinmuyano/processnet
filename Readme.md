# 介绍
- 统计进程出入流量,支持ecs环境/k8s环境
- 支持统计进程下,外网出入流量
- 支持统计指定服务ip:port,出入流量


![image](https://github.com/user-attachments/assets/c636a347-5313-4a25-b710-ffa2dd036c3e)


# 使用方法
cmd/
- |---- cmd_test.go
- ecs环境解析eth0数据包流量
- k8s环境解析calico,cni网卡数据包流量


# 配置
if !strings.HasPrefix(localAddr, "192.168") && !strings.HasPrefix(localAddr, "10.")   此条件成立,则判断为外网流量,根据需要修改.


# 代码流程
- 需要安装vscode插件阅读,vscode-mindmap
- cni0/cni0flow.km
- eth0/flowchart.km
