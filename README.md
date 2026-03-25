# rtp-proxy

基于 UDP 的 RTP 外观隧道代理，支持：

- TCP 代理：SOCKS5 `CONNECT`
- UDP 代理：SOCKS5 `UDP ASSOCIATE`
- 握手后所有业务帧加密传输
- 外层保留 RTP 头部特征：`V=2 / sequence / timestamp / SSRC`
- 抗丢包能力：连接级 ACK 位图、快速重传、超时重传、UDP 冗余双发去重

## 构建

```bash
go build -o rtp-proxy-linux-amd64 .
```

## 运行

服务端：

```bash
./rtp-proxy-linux-amd64 -s 0.0.0.0 -p 10080
```

说明：

- 服务端监听公网 UDP `10080`
- 服务端不启动本地 SOCKS5

客户端：

```bash
./rtp-proxy-linux-amd64 -c 8.8.8.8 -p 10080 -socks5 127.0.0.1:1080 -proxy-user user:pass
```

说明：

- `-c` 指向代理服务端公网 IP
- `-socks5` 是本地 SOCKS5 监听地址
- `-proxy-user` 是本地 SOCKS5 用户名密码认证，格式为 `user:pass`

## 本地测试示例

TCP：

```bash
curl --proxy socks5h://user:pass@127.0.0.1:1080 https://ip.me
curl -I --proxy socks5h://user:pass@127.0.0.1:1080 https://www.baidu.com
```

UDP：

- 可使用支持 SOCKS5 UDP 的客户端走 `UDP ASSOCIATE`
- 仓库开发时已用本地 UDP echo 验证 UDP 端到端可用

## 设计说明

- 外层链路为 UDP，每个隧道包都带标准 12 字节 RTP 风格头
- 握手使用临时 ECDH，业务帧使用 AEAD 加密
- TCP 流按分片封装进可靠帧中传输
- UDP 数据报按独立数据报封装，不做 TCP 化
