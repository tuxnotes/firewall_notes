# 2 Network Layer Attacks  and Defense

This book is concerned mostly with attacks that are delivered over IPv4 networking protocol, though many other networking protocols also exist, such as IPX, X.25 , and the latent IPv6 protocol.

In this chapter, we'll focus first on **how iptables logs network layer packet header within log message output **. Then we'll see **how these logs can be used to catch suspicious network layer activity** .

## 2.1 Logging Network Layer Headers with Iptables

With the iptables LOG target, firewalls built with iptables have the ability to write log data to syslog for nearly every field of the IPv4 headers. Because the iptables logging format is quite thorough , **iptables logs are well-suited to supporting the detection of many network layer header abuses**.

### 2.1.1 Logging the IP Header

The IP header is defined by RFC 791, which describes the structure of the header used by IP. RFC 791定义了IP头部，IP头部描述了IP协议使用的头部结构。图2-1展示了IP头部的结构，阴影部分是iptables在日志消息中包含的信息。在日志信息中，iptables使用标识字符串来标记阴影中每个字段名称。如Total Length 字段使用**LEN=**为前缀的字符串，后面跟着实际total lenght的值。

![ip head](./ip_header.png)

上图中，深色阴影的字段都会被iptables记录到日志中；没有阴影的字段基本不会被输出到日志。对于浅色阴影的字段，ip头部的options信息只有在iptables使用了命令行参数`--log-ip-options` 且LOG规则添加到iptables策略中时才会记录到日志中。

下面是iptables记录日志信息的例子：

```bash
[ext_scanner]$ ping -c 1 71.157.X.X
PING 71.157.X.X (71.157.X.X) 56(84) bytes of data.
64 bytes from 71.157.X.X: icmp_seq=1 ttl=64 time=0.171 ms
--- 71.157.X.X ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.171/0.171/0.171/0.000 ms
[iptablesfw]# tail /var/log/messages | grep ICMP | tail -n 1
Jul 22 15:01:25 iptablesfw kernel: IN=eth0 OUT=
MAC=00:13:d3:38:b6:e4:00:30:48:80:4e:37:08:00 SRC=144.202.X.X DST=71.157.X.X
LEN=84 TOS=0x00 PREC=0x00 TTL=64 ID=0 DF PROTO=ICMP TYPE=8 CODE=0 ID=44366 SEQ=1
```

日志中记录的IP头部的信息开始于源IP地址。其他首部信息如目标IP地址，TTL值，协议等字段以黑体方式呈现。

The Type Of Service field (TOS), and the precedence and corre-
sponding type bits are included as separate hexadecimal values to the TOS
and PREC fields. **The Flags header field in this case is included as the string DF ,
or Don't Fragment , which indicates that IP gateways are not permitted to split the packet into smaller chunks**. Finally, the PROTO field is the protocol encapsulated
by the IP header—ICMP in this case. The remaining fields in the log message
above include the **ICMP TYPE , CODE , ID , and SEQ values in the ICMP Echo
Request packet sent by the ping command**, and are **not part of the IP header**.

### 2.1.2 Logging IP Options

IP options 给IP通信提供了多种控制函数，包括timestamps, certain security capabilities, and provisions for special routing features。IP options的字节长度是不固定的，且在互联网上很少使用。如果没有IP options，一个IP包的头部长度占20个字节。要想日志中记录IP options，需要iptables LOG规则中使用`--log-ip-options`参数：

```bash
[iptablesfw]# iptables -A INPUT -j LOG --log-ip-options
```

接下展示iptables记录IP options日志，继续使用`ping`命令， 但是设定`timestamp`选项为`tsonly`(only timestamp):

```bash
[ext_scanner]$ ping -c 1 -T tsonly 71.157.X.X
PING 71.157.X.X (71.157.X.X) 56(124) bytes of data.
64 bytes from 71.157.X.X icmp_seq=1 ttl=64 time=0.211 ms
TS:		68579524 absolute
		578
		0
		-578
--- 71.157.X.X ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.211/0.211/0.211/0.000 ms
[iptablesfw]# tail /var/log/messages | grep ICMP
Jul 22 15:03:00 iptablesfw kernel: IN=eth0 OUT=
MAC=00:13:d3:38:b6:e4:00:30:48:80:4e:37:08:00 SRC=144.202.X.X DST=71.157.X.X
LEN=124 TOS=0x00 PREC=0x00 TTL=64 ID=0 DF OPT (44280D00041670C404167306000000
00000000000000000000000000000000000000000000000000) PROTO=ICMP TYPE=8 CODE=0
ID=57678 SEQ=1
```

OPT后面是一个十六进制的字节序列，这个字节序列包含了IP头部中IP options的全部信息。但是iptables的LOG target并没有解码。具体在第7章介绍。

### 2.1.3 Logging ICMP

因为ICMP也属于网络层，因此iptables的LOG target可以记录ICMP日志。 RFC 792定义了ICMP头部为32 bits. 如下图所示：

![icmp header](./icmp_header.png)

与IP头部一样，LOG target只会记录type和code字段，不会记录`Checksum`字段，没有参数开启后可以记录`DATA`字段，日志示例如下：

```bash
Jul 22 15:01:25 iptablesfw kernel: IN=eth0 OUT=
MAC=00:13:d3:38:b6:e4:00:30:48:80:4e:37:08:00 SRC=144.202.X.X DST=71.157.X.X
LEN=84 TOS=0x00 PREC=0x00 TTL=64 ID=0 DF PROTO=ICMP
TYPE=8 CODE=0 ID=44366 SEQ=1
```

## 2.2 Network Layer Attack Definitions

网络层攻击定义为：通过对网络层数据包头部的字段进行滥用，来利用末端主机网络协议栈实现的漏洞，达到耗费网络层资源或掩盖(屏蔽)更高层协议数据包的分发。

网络层攻击可以分为以下三类：

- **Header abuses**  Packets that contain maliciously(恶意) constructed , broken, or falsified(篡改) network layer headers, Examples include IP packets with spoofed source addresses and packets that contain unrealistic fragment offset values.
- **Network stack exploits**  