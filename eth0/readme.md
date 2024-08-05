# 实现
1.读取/proc/pid/fd/socket文件,关联pid和socket_id
2.读取/proc/net/tcp,根据socket_id记录ip和port
3.读取/proc/net/tcp6,根据socket_id记录ip和port
4.读取netstat -lnputa,根据ip和port记录pid



