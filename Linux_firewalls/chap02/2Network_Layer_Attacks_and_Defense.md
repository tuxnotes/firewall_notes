# 2 Network Layer Attacks  and Defense

This book is concerned mostly with attacks that are delivered over IPv4 networking protocol, though many other networking protocols also exist, such as IPX, X.25 , and the latent IPv6 protocol.

In this chapter, we'll focus first on **how iptables logs network layer packet header within log message output **. Then we'll see **how these logs can be used to catch suspicious network layer activity** .

## 2.1 Logging Network Layer Headers with Iptables

With the iptables LOG target, firewalls built with iptables have the ability to write log data to syslog for nearly every field of the IPv4 headers. Because the iptables logging format is quite thorough , **iptables logs are well-suited to supporting the detection of many network layer header abuses**.

### 2.1.1 Logging the IP Header

The IP header is defined by RFC 791, which describes the structure of the header used by IP. RFC 791定义了IP头部，IP头部描述了IP协议使用的头部结构。图2-1展示了IP头部的结构，阴影部分是iptables在日志消息中包含的信息。在日志信息中，iptables使用标识字符串来标记阴影中每个字段名称。如Total Length 字段使用**LEN=**为前缀的字符串，后面跟着实际total lenght的值。

![ip head](./ip_header.png)

