package main

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
)

type socks5Server struct {
	listenAddr string
	bindIP     net.IP
	username   string
	password   string
	session    *Session
	logger     *log.Logger
}

func newSocks5Server(listenAddr string, username string, password string, session *Session, logger *log.Logger) *socks5Server {
	host, _, err := net.SplitHostPort(listenAddr)
	if err != nil {
		host = "127.0.0.1"
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.IsUnspecified() {
		ip = net.ParseIP("127.0.0.1")
	}
	return &socks5Server{
		listenAddr: listenAddr,
		bindIP:     ip,
		username:   username,
		password:   password,
		session:    session,
		logger:     logger,
	}
}

func (s *socks5Server) serve(ctx context.Context) error {
	listener, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return err
	}
	defer listener.Close()

	if s.logger != nil {
		s.logger.Printf("local socks5 listening on %s", listener.Addr().String())
	}

	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				continue
			}
			return err
		}
		go s.handleConn(conn)
	}
}

func (s *socks5Server) handleConn(conn net.Conn) {
	handedOff := false
	defer func() {
		if !handedOff {
			_ = conn.Close()
		}
	}()

	version, err := readByte(conn)
	if err != nil {
		return
	}
	if version != 0x05 {
		return
	}
	methodCount, err := readByte(conn)
	if err != nil {
		return
	}
	methods := make([]byte, methodCount)
	if err := readFull(conn, methods); err != nil {
		return
	}

	method := byte(0xff)
	if s.username != "" {
		if hasAuthMethod(methods, 0x02) {
			method = 0x02
		}
	} else if hasAuthMethod(methods, 0x00) {
		method = 0x00
	}

	if _, err := conn.Write([]byte{0x05, method}); err != nil {
		return
	}
	if method == 0xff {
		return
	}

	if method == 0x02 {
		if err := s.handleUserPassAuth(conn); err != nil {
			return
		}
	}

	header := make([]byte, 4)
	if err := readFull(conn, header); err != nil {
		return
	}
	if header[0] != 0x05 {
		return
	}
	cmd := header[1]
	atyp := header[3]
	host, port, err := readSOCKS5Address(conn, atyp)
	if err != nil {
		_ = writeSOCKS5Reply(conn, 0x08, "0.0.0.0", 0)
		return
	}

	switch cmd {
	case 0x01:
		stream, err := s.session.openClientStream(conn, host, port)
		if err != nil {
			if s.logger != nil {
				s.logger.Printf("tcp open failed for %s:%d: %v", host, port, err)
			}
			_ = writeSOCKS5Reply(conn, 0x05, "0.0.0.0", 0)
			return
		}
		localHost, localPort := splitAddr(conn.LocalAddr())
		if err := writeSOCKS5Reply(conn, 0x00, localHost, localPort); err != nil {
			stream.closeLocal()
			return
		}
		stream.start()
		handedOff = true
	case 0x03:
		assoc, err := newClientUDPAssoc(s.session, s.bindIP)
		if err != nil {
			_ = writeSOCKS5Reply(conn, 0x01, "0.0.0.0", 0)
			return
		}
		host, port := splitUDPAddr(assoc.conn.LocalAddr())
		if err := writeSOCKS5Reply(conn, 0x00, host, port); err != nil {
			assoc.close(true)
			return
		}
		handedOff = true
		go func() {
			defer assoc.close(true)
			defer conn.Close()
			_, _ = io.Copy(io.Discard, conn)
		}()
	case 0x02:
		_ = writeSOCKS5Reply(conn, 0x07, "0.0.0.0", 0)
	default:
		_ = writeSOCKS5Reply(conn, 0x07, "0.0.0.0", 0)
	}
}

func (s *socks5Server) handleUserPassAuth(conn net.Conn) error {
	version, err := readByte(conn)
	if err != nil {
		return err
	}
	if version != 0x01 {
		return errors.New("invalid auth version")
	}
	userLen, err := readByte(conn)
	if err != nil {
		return err
	}
	username := make([]byte, userLen)
	if err := readFull(conn, username); err != nil {
		return err
	}
	passLen, err := readByte(conn)
	if err != nil {
		return err
	}
	password := make([]byte, passLen)
	if err := readFull(conn, password); err != nil {
		return err
	}

	status := byte(0x01)
	if string(username) == s.username && string(password) == s.password {
		status = 0x00
	}
	if _, err := conn.Write([]byte{0x01, status}); err != nil {
		return err
	}
	if status != 0x00 {
		return errors.New("invalid username or password")
	}
	return nil
}

func hasAuthMethod(methods []byte, expected byte) bool {
	for _, method := range methods {
		if method == expected {
			return true
		}
	}
	return false
}

func readSOCKS5Address(conn net.Conn, atyp byte) (host string, port uint16, err error) {
	switch atyp {
	case 0x01:
		addr := make([]byte, 4)
		if err = readFull(conn, addr); err != nil {
			return "", 0, err
		}
		host = net.IP(addr).String()
	case 0x03:
		size, readErr := readByte(conn)
		if readErr != nil {
			return "", 0, readErr
		}
		addr := make([]byte, size)
		if err = readFull(conn, addr); err != nil {
			return "", 0, err
		}
		host = string(addr)
	case 0x04:
		addr := make([]byte, 16)
		if err = readFull(conn, addr); err != nil {
			return "", 0, err
		}
		host = net.IP(addr).String()
	default:
		return "", 0, errInvalidFrame
	}
	portBytes := make([]byte, 2)
	if err = readFull(conn, portBytes); err != nil {
		return "", 0, err
	}
	port = uint16(portBytes[0])<<8 | uint16(portBytes[1])
	return host, port, nil
}

func encodeSOCKS5Address(host string) ([]byte, byte, error) {
	ip := net.ParseIP(host)
	if ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return v4, 0x01, nil
		}
		if v6 := ip.To16(); v6 != nil {
			return v6, 0x04, nil
		}
	}
	if len(host) > 255 {
		return nil, 0, errInvalidFrame
	}
	buf := make([]byte, 1+len(host))
	buf[0] = byte(len(host))
	copy(buf[1:], host)
	return buf, 0x03, nil
}

func parseSOCKS5UDPRequest(packet []byte) (host string, port uint16, data []byte, err error) {
	if len(packet) < 4 {
		return "", 0, nil, errInvalidFrame
	}
	if packet[0] != 0x00 || packet[1] != 0x00 {
		return "", 0, nil, errInvalidFrame
	}
	if packet[2] != 0x00 {
		return "", 0, nil, errors.New("udp fragmentation is not supported")
	}
	offset := 3
	host, port, offset, err = decodeSOCKS5AddressFromBytes(packet, offset)
	if err != nil {
		return "", 0, nil, err
	}
	data = append([]byte(nil), packet[offset:]...)
	return host, port, data, nil
}

func buildSOCKS5UDPDatagram(host string, port uint16, data []byte) ([]byte, error) {
	addrBytes, atyp, err := encodeSOCKS5Address(host)
	if err != nil {
		return nil, err
	}
	packet := make([]byte, 3+1+len(addrBytes)+2+len(data))
	packet[0] = 0x00
	packet[1] = 0x00
	packet[2] = 0x00
	packet[3] = atyp
	copy(packet[4:], addrBytes)
	offset := 4 + len(addrBytes)
	packet[offset] = byte(port >> 8)
	packet[offset+1] = byte(port)
	copy(packet[offset+2:], data)
	return packet, nil
}

func decodeSOCKS5AddressFromBytes(packet []byte, offset int) (host string, port uint16, next int, err error) {
	if len(packet) <= offset {
		return "", 0, 0, errInvalidFrame
	}
	atyp := packet[offset]
	offset++
	switch atyp {
	case 0x01:
		if len(packet) < offset+4+2 {
			return "", 0, 0, errInvalidFrame
		}
		host = net.IP(packet[offset : offset+4]).String()
		offset += 4
	case 0x03:
		if len(packet) < offset+1 {
			return "", 0, 0, errInvalidFrame
		}
		size := int(packet[offset])
		offset++
		if len(packet) < offset+size+2 {
			return "", 0, 0, errInvalidFrame
		}
		host = string(packet[offset : offset+size])
		offset += size
	case 0x04:
		if len(packet) < offset+16+2 {
			return "", 0, 0, errInvalidFrame
		}
		host = net.IP(packet[offset : offset+16]).String()
		offset += 16
	default:
		return "", 0, 0, errInvalidFrame
	}
	if len(packet) < offset+2 {
		return "", 0, 0, errInvalidFrame
	}
	port = uint16(packet[offset])<<8 | uint16(packet[offset+1])
	offset += 2
	return host, port, offset, nil
}

func splitAddr(addr net.Addr) (string, uint16) {
	host, portStr, err := net.SplitHostPort(addr.String())
	if err != nil {
		return "0.0.0.0", 0
	}
	portValue, _ := strconv.Atoi(portStr)
	if host == "" || host == "::" || host == "0.0.0.0" {
		host = "127.0.0.1"
	}
	if strings.Contains(host, "%") {
		host = strings.Split(host, "%")[0]
	}
	return host, uint16(portValue)
}

func splitUDPAddr(addr net.Addr) (string, uint16) {
	if udpAddr, ok := addr.(*net.UDPAddr); ok {
		host := udpAddr.IP.String()
		if host == "" || udpAddr.IP.IsUnspecified() {
			host = "127.0.0.1"
		}
		return host, uint16(udpAddr.Port)
	}
	return splitAddr(addr)
}
