package main

import (
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"
)

type serverSessionEntry struct {
	session  *Session
	helloAck []byte
}

func main() {
	var (
		serverBind  string
		serverHost  string
		port        int
		socks5Addr  string
		proxyUser   string
		dialTimeout time.Duration
	)

	flag.StringVar(&serverBind, "s", "", "server listen ip")
	flag.StringVar(&serverHost, "c", "", "server address for client mode")
	flag.IntVar(&port, "p", 10080, "udp port")
	flag.StringVar(&socks5Addr, "socks5", "127.0.0.1:1080", "local socks5 listen address in client mode")
	flag.StringVar(&proxyUser, "proxy-user", "", "local socks5 auth in user:pass format")
	flag.DurationVar(&dialTimeout, "dial-timeout", 12*time.Second, "remote dial timeout")
	flag.Parse()

	logger := log.New(os.Stdout, "", log.LstdFlags|log.Lmicroseconds)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	switch {
	case serverBind != "" && serverHost != "":
		logger.Fatalf("cannot use -s and -c at the same time")
	case serverBind == "" && serverHost == "":
		logger.Fatalf("must use either server mode (-s) or client mode (-c)")
	}

	var err error
	if serverBind != "" {
		err = runServer(ctx, serverBind, port, dialTimeout, logger)
	} else {
		err = runClient(ctx, serverHost, port, socks5Addr, proxyUser, dialTimeout, logger)
	}
	if err != nil && ctx.Err() == nil {
		logger.Fatalf("fatal: %v", err)
	}
}

func runServer(ctx context.Context, bindHost string, port int, dialTimeout time.Duration, logger *log.Logger) error {
	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(bindHost, strconv.Itoa(port)))
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetReadBuffer(4 << 20)
	_ = conn.SetWriteBuffer(4 << 20)

	logger.Printf("server listening on %s", addr.String())
	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()

	var (
		mu       sync.RWMutex
		sessions = make(map[string]*serverSessionEntry)
	)

	removeSession := func(key string, session *Session) {
		mu.Lock()
		entry, ok := sessions[key]
		if ok && entry.session == session {
			delete(sessions, key)
		}
		mu.Unlock()
	}

	buffer := make([]byte, 65535)
	for {
		n, remote, err := conn.ReadFromUDP(buffer)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		payload, err := unwrapRTP(buffer[:n])
		if err != nil || len(payload) == 0 {
			continue
		}

		switch payload[0] {
		case wireTypeHello:
			hello, err := decodeHello(payload)
			if err != nil {
				continue
			}
			key := serverSessionKey(remote, hello.TunnelID)

			mu.RLock()
			existing := sessions[key]
			mu.RUnlock()
			if existing != nil {
				_, _ = conn.WriteToUDP(existing.helloAck, remote)
				continue
			}

			serverPriv, serverPub, err := generateKeyPair()
			if err != nil {
				return err
			}
			serverSalt, err := randomSalt()
			if err != nil {
				return err
			}
			shared, err := deriveSharedSecret(serverPriv, hello.Public)
			if err != nil {
				continue
			}
			clientKey, serverKey, clientNonce, serverNonce, err := deriveSessionKeys(shared, hello.Salt, serverSalt)
			if err != nil {
				return err
			}
			rtp, err := newRTPState()
			if err != nil {
				return err
			}

			session, err := newSession(conn, remote, hello.TunnelID, serverKey, clientKey, serverNonce, clientNonce, rtp, logger, false, dialTimeout, nil)
			if err != nil {
				return err
			}
			session.onClose = func(closed *Session) {
				removeSession(key, closed)
			}

			helloAck := wrapRTP(rtp, false, encodeHello(wireTypeHelloAck, helloPacket{
				TunnelID: hello.TunnelID,
				Salt:     serverSalt,
				Public:   serverPub,
			}), rtpMinOuterPayload)

			mu.Lock()
			sessions[key] = &serverSessionEntry{session: session, helloAck: helloAck}
			mu.Unlock()

			session.start(ctx)
			_, _ = conn.WriteToUDP(helloAck, remote)
			logger.Printf("new session %016x from %s", hello.TunnelID, remote.String())

		case wireTypeData:
			if len(payload) < 9 {
				continue
			}
			tunnelID := binary.BigEndian.Uint64(payload[1:9])
			key := serverSessionKey(remote, tunnelID)

			mu.RLock()
			entry := sessions[key]
			mu.RUnlock()
			if entry == nil {
				continue
			}
			if err := entry.session.handlePayload(payload); err != nil && logger != nil {
				logger.Printf("session %016x packet error: %v", tunnelID, err)
			}
		}
	}
}

func runClient(ctx context.Context, serverHost string, port int, socks5Addr, proxyUser string, dialTimeout time.Duration, logger *log.Logger) error {
	username, password, err := parseProxyUser(proxyUser)
	if err != nil {
		return err
	}

	remote, err := net.ResolveUDPAddr("udp", net.JoinHostPort(serverHost, strconv.Itoa(port)))
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetReadBuffer(4 << 20)
	_ = conn.SetWriteBuffer(4 << 20)

	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()

	session, err := handshakeClient(ctx, conn, remote, dialTimeout, logger)
	if err != nil {
		return err
	}
	session.start(ctx)
	go clientReadLoop(ctx, conn, session, logger)

	logger.Printf("client tunnel ready: server=%s socks5=%s", remote.String(), socks5Addr)
	server := newSocks5Server(socks5Addr, username, password, session, logger)
	return server.serve(ctx)
}

func handshakeClient(ctx context.Context, conn *net.UDPConn, remote *net.UDPAddr, dialTimeout time.Duration, logger *log.Logger) (*Session, error) {
	rtp, err := newRTPState()
	if err != nil {
		return nil, err
	}
	tunnelID, err := generateTunnelID()
	if err != nil {
		return nil, err
	}
	clientPriv, clientPub, err := generateKeyPair()
	if err != nil {
		return nil, err
	}
	clientSalt, err := randomSalt()
	if err != nil {
		return nil, err
	}
	hello := wrapRTP(rtp, false, encodeHello(wireTypeHello, helloPacket{
		TunnelID: tunnelID,
		Salt:     clientSalt,
		Public:   clientPub,
	}), rtpMinOuterPayload)

	buffer := make([]byte, 65535)
	deadline := time.Now().Add(dialTimeout)
	for attempt := 0; time.Now().Before(deadline); attempt++ {
		if _, err := conn.WriteToUDP(hello, remote); err != nil {
			return nil, err
		}
		_ = conn.SetReadDeadline(time.Now().Add(1200 * time.Millisecond))
		for {
			n, addr, err := conn.ReadFromUDP(buffer)
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					break
				}
				return nil, err
			}
			if addr.String() != remote.String() {
				continue
			}
			payload, err := unwrapRTP(buffer[:n])
			if err != nil || len(payload) == 0 || payload[0] != wireTypeHelloAck {
				continue
			}
			reply, err := decodeHello(payload)
			if err != nil || reply.TunnelID != tunnelID {
				continue
			}
			shared, err := deriveSharedSecret(clientPriv, reply.Public)
			if err != nil {
				return nil, err
			}
			clientKey, serverKey, clientNonce, serverNonce, err := deriveSessionKeys(shared, clientSalt, reply.Salt)
			if err != nil {
				return nil, err
			}
			_ = conn.SetReadDeadline(time.Time{})
			session, err := newSession(conn, remote, tunnelID, clientKey, serverKey, clientNonce, serverNonce, rtp, logger, true, dialTimeout, nil)
			if err != nil {
				return nil, err
			}
			logger.Printf("handshake completed with %s, tunnel=%016x", remote.String(), tunnelID)
			return session, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
	return nil, fmt.Errorf("handshake timeout to %s", remote.String())
}

func clientReadLoop(ctx context.Context, conn *net.UDPConn, session *Session, logger *log.Logger) {
	buffer := make([]byte, 65535)
	for {
		n, _, err := conn.ReadFromUDP(buffer)
		if err != nil {
			if ctx.Err() == nil {
				session.closeWithReason(err.Error())
				if logger != nil {
					logger.Printf("client read loop stopped: %v", err)
				}
			}
			return
		}
		payload, err := unwrapRTP(buffer[:n])
		if err != nil || len(payload) == 0 || payload[0] != wireTypeData {
			continue
		}
		if err := session.handlePayload(payload); err != nil && logger != nil {
			logger.Printf("client packet error: %v", err)
		}
	}
}

func serverSessionKey(addr *net.UDPAddr, tunnelID uint64) string {
	return addr.String() + "#" + fmt.Sprintf("%016x", tunnelID)
}
