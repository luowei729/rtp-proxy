package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	maxInFlightPackets = 512
	maxInFlightBytes   = 8 << 20
	retransmitAfter    = 250 * time.Millisecond
	keepAliveInterval  = 10 * time.Second
	ackThrottle        = 60 * time.Millisecond
	tcpChunkSize       = 900
	udpRedundancyDelay = 12 * time.Millisecond
	dataPaceInterval   = 1 * time.Millisecond
	rtpMinOuterPayload = 160
	rtpControlPlainMin = 64
)

type sentPacket struct {
	number      uint64
	datagram    []byte
	sentAt      time.Time
	retransmits int
	fastLosses  int
	size        int
	frameType   byte
}

type Session struct {
	conn        *net.UDPConn
	remote      *net.UDPAddr
	tunnelID    uint64
	sendAEAD    cipher.AEAD
	recvAEAD    cipher.AEAD
	sendNonce   [4]byte
	recvNonce   [4]byte
	rtp         *rtpState
	logger      *log.Logger
	clientMode  bool
	dialTimeout time.Duration
	onClose     func(*Session)

	streamMu     sync.RWMutex
	streams      map[uint32]*tcpStream
	nextStreamID uint32

	assocMu     sync.RWMutex
	assocs      map[uint32]udpAssociation
	nextAssocID uint32

	sendCounter   uint64
	writeMu       sync.Mutex
	sentMu        sync.Mutex
	sentCond      *sync.Cond
	sentPackets   map[uint64]*sentPacket
	inFlightBytes int

	recvMu    sync.Mutex
	recvTrack recvTracker

	lastSend    int64
	lastRecv    int64
	lastAckSent int64
	closedFlag  int32
	closed      chan struct{}
}

type openResult struct {
	ok      bool
	message string
}

type tcpStream struct {
	id      uint32
	session *Session
	conn    net.Conn
	logger  *log.Logger

	openCh   chan openResult
	sendMu   sync.Mutex
	sendOff  uint64
	localEOF bool

	recvMu      sync.Mutex
	recvNext    uint64
	recvBuf     map[uint64][]byte
	remoteFinal *uint64
	writeClosed bool

	closeOnce sync.Once
}

type udpAssociation interface {
	handleRemotePacket(datagramID uint32, host string, port uint16, data []byte)
	close(sendClose bool)
}

type clientUDPAssoc struct {
	id        uint32
	session   *Session
	conn      *net.UDPConn
	logger    *log.Logger
	clientMu  sync.RWMutex
	client    *net.UDPAddr
	sendID    uint32
	recvMu    sync.Mutex
	lastRecv  uint32
	recvBits  uint64
	closeOnce sync.Once
}

type serverUDPAssoc struct {
	id        uint32
	session   *Session
	conn      *net.UDPConn
	logger    *log.Logger
	sendID    uint32
	recvMu    sync.Mutex
	lastRecv  uint32
	recvBits  uint64
	closeOnce sync.Once
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func newSession(conn *net.UDPConn, remote *net.UDPAddr, tunnelID uint64, sendKey, recvKey []byte, sendNonce, recvNonce [4]byte, rtp *rtpState, logger *log.Logger, clientMode bool, dialTimeout time.Duration, onClose func(*Session)) (*Session, error) {
	sendAEAD, err := newAEAD(sendKey)
	if err != nil {
		return nil, err
	}
	recvAEAD, err := newAEAD(recvKey)
	if err != nil {
		return nil, err
	}
	s := &Session{
		conn:        conn,
		remote:      remote,
		tunnelID:    tunnelID,
		sendAEAD:    sendAEAD,
		recvAEAD:    recvAEAD,
		sendNonce:   sendNonce,
		recvNonce:   recvNonce,
		rtp:         rtp,
		logger:      logger,
		clientMode:  clientMode,
		dialTimeout: dialTimeout,
		onClose:     onClose,
		streams:     make(map[uint32]*tcpStream),
		assocs:      make(map[uint32]udpAssociation),
		sentPackets: make(map[uint64]*sentPacket),
		closed:      make(chan struct{}),
	}
	s.sentCond = sync.NewCond(&s.sentMu)
	s.nextStreamID = mustRandomUint32()
	s.nextAssocID = mustRandomUint32()
	now := time.Now().UnixNano()
	atomic.StoreInt64(&s.lastSend, now)
	atomic.StoreInt64(&s.lastRecv, now)
	return s, nil
}

func (s *Session) start(ctx context.Context) {
	go s.retransmitLoop(ctx)
	go s.keepAliveLoop(ctx)
}

func (s *Session) close() {
	s.closeWithReason("session closed")
}

func (s *Session) closeWithReason(reason string) {
	if !atomic.CompareAndSwapInt32(&s.closedFlag, 0, 1) {
		return
	}
	close(s.closed)
	s.sentMu.Lock()
	s.sentCond.Broadcast()
	s.sentMu.Unlock()

	s.streamMu.Lock()
	streams := make([]*tcpStream, 0, len(s.streams))
	for _, st := range s.streams {
		streams = append(streams, st)
	}
	s.streams = make(map[uint32]*tcpStream)
	s.streamMu.Unlock()
	for _, st := range streams {
		st.closeLocal()
	}

	s.assocMu.Lock()
	assocs := make([]udpAssociation, 0, len(s.assocs))
	for _, assoc := range s.assocs {
		assocs = append(assocs, assoc)
	}
	s.assocs = make(map[uint32]udpAssociation)
	s.assocMu.Unlock()
	for _, assoc := range assocs {
		assoc.close(false)
	}

	if s.logger != nil {
		s.logger.Printf("session %016x closed: %s", s.tunnelID, reason)
	}
	if s.onClose != nil {
		s.onClose(s)
	}
}

func (s *Session) waitSendWindow() error {
	s.sentMu.Lock()
	defer s.sentMu.Unlock()
	for len(s.sentPackets) >= maxInFlightPackets || s.inFlightBytes >= maxInFlightBytes {
		if atomic.LoadInt32(&s.closedFlag) == 1 {
			return net.ErrClosed
		}
		s.sentCond.Wait()
	}
	return nil
}

func (s *Session) sendFrame(frameType byte, framePayload []byte, reliable bool) error {
	if atomic.LoadInt32(&s.closedFlag) == 1 {
		return net.ErrClosed
	}
	if reliable {
		if err := s.waitSendWindow(); err != nil {
			return err
		}
	}
	packetNum := atomic.AddUint64(&s.sendCounter, 1)

	s.recvMu.Lock()
	ack, ackBits := s.recvTrack.snapshot()
	s.recvMu.Unlock()

	ciphertext := encryptFrame(s.sendAEAD, s.sendNonce, packetNum, ack, ackBits, frameType, framePayload, s.tunnelID, framePlainMin(frameType))
	payload := encodeDataPayload(s.tunnelID, packetNum, ciphertext)
	datagram := wrapRTP(s.rtp, false, payload, framePadTarget(len(payload)))
	if reliable {
		s.sentMu.Lock()
		s.sentPackets[packetNum] = &sentPacket{
			number:    packetNum,
			datagram:  datagram,
			sentAt:    time.Now(),
			size:      len(datagram),
			frameType: frameType,
		}
		s.inFlightBytes += len(datagram)
		s.sentMu.Unlock()
	}

	if err := s.writeDatagram(datagram, frameType); err != nil {
		return err
	}
	atomic.StoreInt64(&s.lastSend, time.Now().UnixNano())
	return nil
}

func (s *Session) handlePayload(payload []byte) error {
	tunnelID, packetNum, ciphertext, err := decodeDataPayload(payload)
	if err != nil {
		return err
	}
	if tunnelID != s.tunnelID {
		return errInvalidFrame
	}

	hdr, framePayload, err := decryptFrame(s.recvAEAD, s.recvNonce, tunnelID, packetNum, ciphertext)
	if err != nil {
		return err
	}
	atomic.StoreInt64(&s.lastRecv, time.Now().UnixNano())
	s.processAcks(hdr.Ack, hdr.AckBits)

	s.recvMu.Lock()
	isNew := s.recvTrack.mark(packetNum)
	s.recvMu.Unlock()
	if !isNew {
		s.maybeSendAck()
		return nil
	}

	if err := s.dispatchFrame(hdr.FrameType, framePayload); err != nil {
		return err
	}
	s.maybeSendAck()
	return nil
}

func (s *Session) processAcks(ack, ackBits uint64) {
	if ack == 0 {
		return
	}
	now := time.Now()
	var resend []*sentPacket
	s.sentMu.Lock()
	for packetNum, pkt := range s.sentPackets {
		if packetAcked(packetNum, ack, ackBits) {
			delete(s.sentPackets, packetNum)
			s.inFlightBytes -= pkt.size
			continue
		}
		if packetNum < ack && ack-packetNum <= 64 {
			pkt.fastLosses++
			if pkt.fastLosses >= 3 && now.Sub(pkt.sentAt) >= 60*time.Millisecond {
				pkt.fastLosses = 0
				pkt.sentAt = now
				pkt.retransmits++
				resend = append(resend, pkt)
			}
		}
	}
	s.sentCond.Broadcast()
	s.sentMu.Unlock()
	for _, pkt := range resend {
		if err := s.writeDatagram(pkt.datagram, pkt.frameType); err != nil && s.logger != nil {
			s.logger.Printf("fast retransmit failed for packet %d: %v", pkt.number, err)
		}
	}
}

func (s *Session) maybeSendAck() {
	now := time.Now().UnixNano()
	last := atomic.LoadInt64(&s.lastAckSent)
	if now-last < ackThrottle.Nanoseconds() {
		return
	}
	if !atomic.CompareAndSwapInt64(&s.lastAckSent, last, now) {
		return
	}
	_ = s.sendFrame(frameTypeNoop, nil, false)
}

func (s *Session) retransmitLoop(ctx context.Context) {
	ticker := time.NewTicker(120 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.closed:
			return
		case <-ticker.C:
		}
		now := time.Now()
		var resend []*sentPacket
		s.sentMu.Lock()
		for _, pkt := range s.sentPackets {
			if now.Sub(pkt.sentAt) >= retransmitAfter {
				pkt.sentAt = now
				pkt.retransmits++
				resend = append(resend, pkt)
			}
		}
		s.sentMu.Unlock()
		for _, pkt := range resend {
			if err := s.writeDatagram(pkt.datagram, pkt.frameType); err != nil {
				if s.logger != nil {
					s.logger.Printf("retransmit failed for packet %d: %v", pkt.number, err)
				}
			}
		}
	}
}

func (s *Session) keepAliveLoop(ctx context.Context) {
	ticker := time.NewTicker(keepAliveInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.closed:
			return
		case <-ticker.C:
		}
		lastSend := time.Unix(0, atomic.LoadInt64(&s.lastSend))
		if time.Since(lastSend) >= keepAliveInterval {
			_ = s.sendFrame(frameTypeNoop, nil, false)
		}
	}
}

func (s *Session) dispatchFrame(frameType byte, payload []byte) error {
	switch frameType {
	case frameTypeNoop:
		return nil
	case frameTypeOpen:
		s.runAsyncFrame("open", func() error { return s.handleOpenFrame(payload) })
		return nil
	case frameTypeOpenResult:
		return s.handleOpenResultFrame(payload)
	case frameTypeData:
		s.runAsyncFrame("data", func() error { return s.handleDataFrame(payload) })
		return nil
	case frameTypeEOF:
		s.runAsyncFrame("eof", func() error { return s.handleEOFFrame(payload) })
		return nil
	case frameTypeReset:
		s.runAsyncFrame("reset", func() error { return s.handleResetFrame(payload) })
		return nil
	case frameTypeUDPPacket:
		s.runAsyncFrame("udp", func() error { return s.handleUDPPacketFrame(payload) })
		return nil
	case frameTypeUDPClose:
		s.runAsyncFrame("udp-close", func() error { return s.handleUDPCloseFrame(payload) })
		return nil
	default:
		return errInvalidFrame
	}
}

func (s *Session) runAsyncFrame(name string, fn func() error) {
	go func() {
		if err := fn(); err != nil && s.logger != nil {
			s.logger.Printf("frame %s error: %v", name, err)
		}
	}()
}

func (s *Session) writeDatagram(datagram []byte, frameType byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	if _, err := s.conn.WriteToUDP(datagram, s.remote); err != nil {
		return err
	}
	if frameType == frameTypeData || frameType == frameTypeUDPPacket {
		time.Sleep(dataPaceInterval)
	}
	return nil
}

func framePlainMin(frameType byte) int {
	switch frameType {
	case frameTypeNoop, frameTypeOpen, frameTypeOpenResult, frameTypeEOF, frameTypeReset, frameTypeUDPClose:
		return rtpControlPlainMin
	default:
		return 0
	}
}

func framePadTarget(payloadLen int) int {
	if payloadLen < rtpMinOuterPayload {
		return rtpMinOuterPayload
	}
	return payloadLen
}

func (s *Session) handleOpenFrame(payload []byte) error {
	if s.clientMode {
		return nil
	}
	streamID, host, port, err := decodeOpenFrame(payload)
	if err != nil {
		return err
	}
	s.streamMu.RLock()
	_, exists := s.streams[streamID]
	s.streamMu.RUnlock()
	if exists {
		return nil
	}
	addr := joinHostPort(host, port)
	conn, err := net.DialTimeout("tcp", addr, s.dialTimeout)
	if err != nil {
		if s.logger != nil {
			s.logger.Printf("server dial failed for stream %d -> %s: %v", streamID, addr, err)
		}
		_ = s.sendFrame(frameTypeOpenResult, encodeOpenResultFrame(streamID, false, err.Error()), true)
		return nil
	}
	stream := newTCPStream(s, streamID, conn, nil)
	s.addStream(stream)
	if err := s.sendFrame(frameTypeOpenResult, encodeOpenResultFrame(streamID, true, ""), true); err != nil {
		stream.closeLocal()
		return err
	}
	stream.start()
	return nil
}

func (s *Session) handleOpenResultFrame(payload []byte) error {
	if !s.clientMode {
		return nil
	}
	streamID, ok, message, err := decodeOpenResultFrame(payload)
	if err != nil {
		return err
	}
	stream := s.getStream(streamID)
	if stream == nil || stream.openCh == nil {
		return nil
	}
	select {
	case stream.openCh <- openResult{ok: ok, message: message}:
	default:
	}
	return nil
}

func (s *Session) handleDataFrame(payload []byte) error {
	streamID, offset, data, err := decodeStreamDataFrame(payload)
	if err != nil {
		return err
	}
	stream := s.getStream(streamID)
	if stream == nil {
		return nil
	}
	return stream.handleData(offset, data)
}

func (s *Session) handleEOFFrame(payload []byte) error {
	streamID, finalOffset, err := decodeEOFFrame(payload)
	if err != nil {
		return err
	}
	stream := s.getStream(streamID)
	if stream == nil {
		return nil
	}
	return stream.handleEOF(finalOffset)
}

func (s *Session) handleResetFrame(payload []byte) error {
	streamID, _, message, err := decodeResetFrame(payload)
	if err != nil {
		return err
	}
	stream := s.getStream(streamID)
	if stream == nil {
		return nil
	}
	stream.closeWithMessage(message)
	return nil
}

func (s *Session) handleUDPPacketFrame(payload []byte) error {
	assocID, datagramID, host, port, data, err := decodeUDPPacketFrame(payload)
	if err != nil {
		return err
	}
	if s.clientMode {
		assoc := s.getAssoc(assocID)
		if assoc != nil {
			assoc.handleRemotePacket(datagramID, host, port, data)
		}
		return nil
	}

	assoc := s.getAssoc(assocID)
	if assoc == nil {
		serverAssoc, err := newServerUDPAssoc(s, assocID)
		if err != nil {
			return err
		}
		s.addAssoc(assocID, serverAssoc)
		assoc = serverAssoc
	}
	assoc.handleRemotePacket(datagramID, host, port, data)
	return nil
}

func (s *Session) handleUDPCloseFrame(payload []byte) error {
	assocID, err := decodeUDPCloseFrame(payload)
	if err != nil {
		return err
	}
	s.removeAssoc(assocID, false)
	return nil
}

func (s *Session) nextClientStreamID() uint32 {
	return atomic.AddUint32(&s.nextStreamID, 1)
}

func (s *Session) nextClientAssocID() uint32 {
	return atomic.AddUint32(&s.nextAssocID, 1)
}

func newTCPStream(session *Session, id uint32, conn net.Conn, openCh chan openResult) *tcpStream {
	return &tcpStream{
		id:      id,
		session: session,
		conn:    conn,
		logger:  session.logger,
		openCh:  openCh,
		recvBuf: make(map[uint64][]byte),
	}
}

func (s *Session) addStream(stream *tcpStream) {
	s.streamMu.Lock()
	s.streams[stream.id] = stream
	s.streamMu.Unlock()
}

func (s *Session) getStream(streamID uint32) *tcpStream {
	s.streamMu.RLock()
	stream := s.streams[streamID]
	s.streamMu.RUnlock()
	return stream
}

func (s *Session) removeStream(streamID uint32) {
	s.streamMu.Lock()
	delete(s.streams, streamID)
	s.streamMu.Unlock()
}

func (s *Session) addAssoc(id uint32, assoc udpAssociation) {
	s.assocMu.Lock()
	s.assocs[id] = assoc
	s.assocMu.Unlock()
}

func (s *Session) getAssoc(id uint32) udpAssociation {
	s.assocMu.RLock()
	assoc := s.assocs[id]
	s.assocMu.RUnlock()
	return assoc
}

func (s *Session) removeAssoc(id uint32, sendClose bool) {
	s.assocMu.Lock()
	assoc := s.assocs[id]
	delete(s.assocs, id)
	s.assocMu.Unlock()
	if assoc != nil {
		assoc.close(sendClose)
	}
}

func (s *Session) openClientStream(conn net.Conn, targetHost string, targetPort uint16) (*tcpStream, error) {
	streamID := s.nextClientStreamID()
	stream := newTCPStream(s, streamID, conn, make(chan openResult, 1))
	s.addStream(stream)
	if err := s.sendFrame(frameTypeOpen, encodeOpenFrame(streamID, targetHost, targetPort), true); err != nil {
		s.removeStream(streamID)
		return nil, err
	}
	select {
	case result := <-stream.openCh:
		if !result.ok {
			s.removeStream(streamID)
			return nil, errors.New(result.message)
		}
		return stream, nil
	case <-time.After(s.dialTimeout):
		s.removeStream(streamID)
		return nil, errors.New("remote connect timeout")
	case <-s.closed:
		s.removeStream(streamID)
		return nil, net.ErrClosed
	}
}

func (s *Session) sendStreamData(streamID uint32, offset uint64, data []byte) error {
	return s.sendFrame(frameTypeData, encodeStreamDataFrame(streamID, offset, data), true)
}

func (s *Session) sendStreamEOF(streamID uint32, finalOffset uint64) error {
	return s.sendFrame(frameTypeEOF, encodeEOFFrame(streamID, finalOffset), true)
}

func (s *Session) sendStreamReset(streamID uint32, code byte, message string) error {
	return s.sendFrame(frameTypeReset, encodeResetFrame(streamID, code, message), true)
}

func (s *Session) sendUDPPacket(assocID uint32, datagramID uint32, host string, port uint16, data []byte) error {
	payload := encodeUDPPacketFrame(assocID, datagramID, host, port, data)
	if err := s.sendFrame(frameTypeUDPPacket, payload, false); err != nil {
		return err
	}
	time.AfterFunc(udpRedundancyDelay, func() {
		_ = s.sendFrame(frameTypeUDPPacket, payload, false)
	})
	return nil
}

func (s *Session) sendUDPClose(assocID uint32) error {
	return s.sendFrame(frameTypeUDPClose, encodeUDPCloseFrame(assocID), true)
}

func (st *tcpStream) start() {
	go st.pump()
}

func (st *tcpStream) pump() {
	buffer := make([]byte, tcpChunkSize)
	for {
		n, err := st.conn.Read(buffer)
		if n > 0 {
			chunk := append([]byte(nil), buffer[:n]...)
			st.sendMu.Lock()
			offset := st.sendOff
			st.sendOff += uint64(len(chunk))
			st.sendMu.Unlock()
			if err := st.session.sendStreamData(st.id, offset, chunk); err != nil {
				st.closeWithMessage(err.Error())
				return
			}
		}
		if err != nil {
			if err == io.EOF {
				st.sendMu.Lock()
				finalOffset := st.sendOff
				st.localEOF = true
				st.sendMu.Unlock()
				_ = st.session.sendStreamEOF(st.id, finalOffset)
				st.maybeFinish()
				return
			}
			_ = st.session.sendStreamReset(st.id, streamResetGeneric, err.Error())
			st.closeWithMessage(err.Error())
			return
		}
	}
}

func (st *tcpStream) handleData(offset uint64, data []byte) error {
	st.recvMu.Lock()

	if len(data) == 0 {
		st.recvMu.Unlock()
		return nil
	}
	if offset < st.recvNext {
		trim := st.recvNext - offset
		if trim >= uint64(len(data)) {
			st.recvMu.Unlock()
			return nil
		}
		data = data[trim:]
		offset = st.recvNext
	}
	if offset > st.recvNext {
		if _, exists := st.recvBuf[offset]; !exists {
			st.recvBuf[offset] = data
		}
		st.recvMu.Unlock()
		return nil
	}

	if err := st.writeAll(data); err != nil {
		st.recvMu.Unlock()
		_ = st.session.sendStreamReset(st.id, streamResetGeneric, err.Error())
		st.closeWithMessage(err.Error())
		return err
	}
	st.recvNext += uint64(len(data))

	for {
		next, ok := st.recvBuf[st.recvNext]
		if !ok {
			break
		}
		delete(st.recvBuf, st.recvNext)
		if err := st.writeAll(next); err != nil {
			st.recvMu.Unlock()
			_ = st.session.sendStreamReset(st.id, streamResetGeneric, err.Error())
			st.closeWithMessage(err.Error())
			return err
		}
		st.recvNext += uint64(len(next))
	}

	if st.remoteFinal != nil && st.recvNext >= *st.remoteFinal {
		st.recvMu.Unlock()
		st.closeWriteSide()
		st.maybeFinish()
		return nil
	}
	st.recvMu.Unlock()
	st.maybeFinish()
	return nil
}

func (st *tcpStream) handleEOF(finalOffset uint64) error {
	st.recvMu.Lock()
	st.remoteFinal = &finalOffset
	ready := st.recvNext >= finalOffset
	st.recvMu.Unlock()
	if ready {
		st.closeWriteSide()
	}
	st.maybeFinish()
	return nil
}

func (st *tcpStream) writeAll(data []byte) error {
	for len(data) > 0 {
		n, err := st.conn.Write(data)
		if err != nil {
			return err
		}
		data = data[n:]
	}
	return nil
}

func (st *tcpStream) closeWriteSide() {
	st.recvMu.Lock()
	if st.writeClosed {
		st.recvMu.Unlock()
		return
	}
	st.writeClosed = true
	st.recvMu.Unlock()
	type closeWriter interface {
		CloseWrite() error
	}
	if cw, ok := st.conn.(closeWriter); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = st.conn.Close()
}

func (st *tcpStream) maybeFinish() {
	st.sendMu.Lock()
	localDone := st.localEOF
	st.sendMu.Unlock()

	st.recvMu.Lock()
	remoteDone := st.remoteFinal != nil && st.recvNext >= *st.remoteFinal
	st.recvMu.Unlock()

	if localDone && remoteDone {
		st.closeLocal()
	}
}

func (st *tcpStream) closeLocal() {
	st.closeOnce.Do(func() {
		_ = st.conn.Close()
		st.session.removeStream(st.id)
	})
}

func (st *tcpStream) closeWithMessage(message string) {
	if message != "" && st.logger != nil {
		st.logger.Printf("stream %d closed: %s", st.id, message)
	}
	st.closeLocal()
}

func newClientUDPAssoc(session *Session, bindIP net.IP) (*clientUDPAssoc, error) {
	addr := &net.UDPAddr{IP: bindIP, Port: 0}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, err
	}
	assoc := &clientUDPAssoc{
		id:      session.nextClientAssocID(),
		session: session,
		conn:    conn,
		logger:  session.logger,
	}
	session.addAssoc(assoc.id, assoc)
	go assoc.readLoop()
	return assoc, nil
}

func (a *clientUDPAssoc) readLoop() {
	buffer := make([]byte, 65535)
	for {
		n, clientAddr, err := a.conn.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		host, port, data, err := parseSOCKS5UDPRequest(buffer[:n])
		if err != nil {
			if a.logger != nil {
				a.logger.Printf("udp associate %d parse error: %v", a.id, err)
			}
			continue
		}
		a.clientMu.Lock()
		a.client = clientAddr
		a.clientMu.Unlock()
		datagramID := atomic.AddUint32(&a.sendID, 1)
		if err := a.session.sendUDPPacket(a.id, datagramID, host, port, data); err != nil && a.logger != nil {
			a.logger.Printf("udp associate %d send error: %v", a.id, err)
		}
	}
}

func (a *clientUDPAssoc) handleRemotePacket(datagramID uint32, host string, port uint16, data []byte) {
	if !markUDPDatagram(&a.recvMu, &a.lastRecv, &a.recvBits, datagramID) {
		return
	}
	packet, err := buildSOCKS5UDPDatagram(host, port, data)
	if err != nil {
		if a.logger != nil {
			a.logger.Printf("udp associate %d build response error: %v", a.id, err)
		}
		return
	}
	a.clientMu.RLock()
	clientAddr := a.client
	a.clientMu.RUnlock()
	if clientAddr == nil {
		return
	}
	_, _ = a.conn.WriteToUDP(packet, clientAddr)
}

func (a *clientUDPAssoc) close(sendClose bool) {
	a.closeOnce.Do(func() {
		if sendClose {
			_ = a.session.sendUDPClose(a.id)
		}
		_ = a.conn.Close()
		a.session.assocMu.Lock()
		delete(a.session.assocs, a.id)
		a.session.assocMu.Unlock()
	})
}

func newServerUDPAssoc(session *Session, id uint32) (*serverUDPAssoc, error) {
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}
	assoc := &serverUDPAssoc{
		id:      id,
		session: session,
		conn:    conn,
		logger:  session.logger,
	}
	go assoc.readLoop()
	return assoc, nil
}

func (a *serverUDPAssoc) readLoop() {
	buffer := make([]byte, 65535)
	for {
		n, addr, err := a.conn.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		host := addr.IP.String()
		if strings.Contains(host, ":") && addr.Zone != "" {
			host = addr.IP.String()
		}
		data := append([]byte(nil), buffer[:n]...)
		datagramID := atomic.AddUint32(&a.sendID, 1)
		if err := a.session.sendUDPPacket(a.id, datagramID, host, uint16(addr.Port), data); err != nil && a.logger != nil {
			a.logger.Printf("server udp assoc %d return error: %v", a.id, err)
		}
	}
}

func (a *serverUDPAssoc) handleRemotePacket(datagramID uint32, host string, port uint16, data []byte) {
	if !markUDPDatagram(&a.recvMu, &a.lastRecv, &a.recvBits, datagramID) {
		return
	}
	target, err := net.ResolveUDPAddr("udp", joinHostPort(host, port))
	if err != nil {
		if a.logger != nil {
			a.logger.Printf("server udp assoc %d resolve error: %v", a.id, err)
		}
		return
	}
	_, _ = a.conn.WriteToUDP(data, target)
}

func (a *serverUDPAssoc) close(sendClose bool) {
	a.closeOnce.Do(func() {
		if sendClose {
			_ = a.session.sendUDPClose(a.id)
		}
		_ = a.conn.Close()
		a.session.assocMu.Lock()
		delete(a.session.assocs, a.id)
		a.session.assocMu.Unlock()
	})
}

func parseProxyUser(value string) (username, password string, err error) {
	if value == "" {
		return "", "", nil
	}
	parts := strings.SplitN(value, ":", 2)
	if len(parts) != 2 || parts[0] == "" {
		return "", "", fmt.Errorf("invalid -proxy-user, expected user:pass")
	}
	return parts[0], parts[1], nil
}

func readFull(conn net.Conn, buf []byte) error {
	_, err := io.ReadFull(conn, buf)
	return err
}

func readByte(conn net.Conn) (byte, error) {
	var one [1]byte
	if err := readFull(conn, one[:]); err != nil {
		return 0, err
	}
	return one[0], nil
}

func writeSOCKS5Reply(conn net.Conn, rep byte, host string, port uint16) error {
	addrBytes, atyp, err := encodeSOCKS5Address(host)
	if err != nil {
		return err
	}
	reply := make([]byte, 4+len(addrBytes)+2)
	reply[0] = 0x05
	reply[1] = rep
	reply[2] = 0x00
	reply[3] = atyp
	copy(reply[4:], addrBytes)
	binary.BigEndian.PutUint16(reply[4+len(addrBytes):], port)
	_, err = conn.Write(reply)
	return err
}

func markUDPDatagram(mu *sync.Mutex, last *uint32, bits *uint64, datagramID uint32) bool {
	if datagramID == 0 {
		return false
	}
	mu.Lock()
	defer mu.Unlock()

	if *last == 0 {
		*last = datagramID
		*bits = 0
		return true
	}
	if datagramID > *last {
		delta := datagramID - *last
		if delta >= 64 {
			*bits = 0
		} else {
			*bits <<= delta
			*bits |= uint64(1) << (delta - 1)
		}
		*last = datagramID
		return true
	}
	if datagramID == *last {
		return false
	}
	diff := *last - datagramID
	if diff > 64 {
		return false
	}
	mask := uint64(1) << (diff - 1)
	already := *bits&mask != 0
	*bits |= mask
	return !already
}
