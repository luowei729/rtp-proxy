# rtp-proxy

基于 UDP 的 RTP 外观隧道代理，支持：

- TCP 代理：SOCKS5 `CONNECT`
- UDP 代理：SOCKS5 `UDP ASSOCIATE`
- 握手后所有业务帧加密传输
- 外层保留 RTP 头部特征：`V=2 / sequence / timestamp / SSRC`
- 抗丢包能力：连接级 ACK 位图、快速重传、超时重传、UDP 冗余双发去重

## 构建

本地编译 `linux/amd64`：

```bash
go build -o rtp-proxy-linux-amd64 .
```

本地交叉编译：

```bash
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o rtp-proxy-linux-amd64 .
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o rtp-proxy-linux-arm64 .
```

## GitHub Actions

- 工作流文件：`.github/workflows/build-release.yml`
- 手动编译：在 GitHub 仓库的 `Actions` 页面运行 `Build Release Artifacts`
- 自动编译：每次新建并发布 Release 后，Actions 会自动构建并上传以下文件到 Release：
  - `rtp-proxy-linux-amd64.tar.gz`
  - `rtp-proxy-linux-arm64.tar.gz`
  - `sha256sums.txt`

下载 Release 后解压示例：

```bash
tar -xzf rtp-proxy-linux-amd64.tar.gz
chmod +x rtp-proxy-linux-amd64
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

- 外层链路为 UDP，隧道数据统一封装成 RTP 风格数据包，保留 `V=2 / PT / sequence / timestamp / SSRC` 等头部特征
- RTP 时间戳使用 `90kHz` 时钟，按 `20ms` 步进推进；小包会使用 RTP padding 补齐，尽量保持更稳定的包形态
- 握手阶段使用临时 `ECDH(P-256)` 交换密钥，再通过 `HKDF-SHA256` 派生会话密钥
- 握手完成后，所有业务帧都使用 `AES-GCM` 加密传输，不明文传输代理内容
- TCP 代理数据在 UDP 隧道上走一层自定义可靠传输，带连接级 `ACK` 位图、快速重传和超时重传
- UDP 代理走 `SOCKS5 UDP ASSOCIATE`，保持数据报语义，不把 UDP 强行 TCP 化
- UDP 数据报额外带冗余双发和去重处理，用于改善较差网络下的丢包影响
- 控制帧和小包会做最小长度填充，业务数据发送带轻微 pacing，减少过于突兀的包长和发送节奏
