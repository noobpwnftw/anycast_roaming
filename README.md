# Anycast Roaming

多个POP之间会话漫游及回程路径关联  

mode=0 漫游（边缘节点，远程会话ingress通过隧道传递）  
mode=1 转发（边缘节点，转发全部ingress流量）  
mode=2 隧道（汇聚节点，通过隧道egress）  
mode=3 中继（中继节点，节点间路径调节）  

reroute=N 漫游分流N%的ingress流量至配置中的第一个节点

转发模式的目标节点为配置中的最后一个节点  
隧道及中继模式的默认回程路径为配置中的第一个节点  

整体流程：  
收包 -> {查询会话状态(更新回程路径)-> [转发对应POP]} -> 收包  
发包 -> {更新会话状态(查询回程路径)-> [转发对应POP]} -> 发包  

{}内为模块实现的功能，转发模式只做()和[]  

满足以下条件，开始发起会话同步：  
TCP发包不是SYNACK、FIN、RST  
UDP发包源端口在ip_local_port_range之内  
ICMP发包类型为ICMP_ECHO、ICMP_TIMESTAMP、ICMP_INFO_REQUEST、ICMP_ADDRESS  

单播通道使用ICMP_ECHOREPLY通讯  
路由变化本身比较罕见，丢包或延迟造成的会话状态不同步，通过网络本身的重传机制自然解决  
由于可能已经存在路径关联，所以漫游模式应避免用Anycast IP往外发起会话，转发模式则应从转发目标往外发起会话  

## Install

#### build kmod
```
cmake .
make
insmod src/anycast_roaming.ko
```

### proc sys ctl

可以通过读写以下文件来修改配置  

- /proc/sys/net/anycast_roaming/config

```
<anycast_ip1>:<mode>:<reroute>:<notify_ip1>,<notify_ip2>,...;<anycast_ip2>:<mode>:<reroute>:<notify_ip1>,<notify_ip2>,...;...
```

可以通过修改以下文件来设置连接超时回收的时间  

- /proc/sys/net/anycast_roaming/idle_timeout (defualt 310s)
- /proc/sys/net/anycast_roaming/notify_interval (defualt 130s)

查看计数器  

- /proc/net/anycast_roaming_stats
