package main

import (
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	mrand "math/rand"
	"net"
	"sync"
	"time"
)

const (
	protocolVersion = 1
	rtpHeaderSize   = 12
	rtpPayloadType  = 96

	wireTypeHello    = 1
	wireTypeHelloAck = 2
	wireTypeData     = 3

	frameTypeNoop       = 0
	frameTypeOpen       = 1
	frameTypeOpenResult = 2
	frameTypeData       = 3
	frameTypeEOF        = 4
	frameTypeReset      = 5
	frameTypeUDPPacket  = 6
	frameTypeUDPClose   = 7

	streamResetGeneric  = 1
	streamResetDial     = 2
	streamResetProtocol = 3
)

var (
	errShortPacket        = errors.New("packet too short")
	errInvalidRTPVersion  = errors.New("invalid rtp version")
	errInvalidVersion     = errors.New("invalid protocol version")
	errInvalidFrame       = errors.New("invalid frame")
	errInvalidHandshake   = errors.New("invalid handshake")
	errUnsupportedCommand = errors.New("unsupported socks5 command")
)

type rtpState struct {
	mu  sync.Mutex
	rng *mrand.Rand
}

type helloPacket struct {
	TunnelID uint64
	Salt     [16]byte
	Public   []byte
}

type frameHeader struct {
	Ack       uint64
	AckBits   uint64
	FrameType byte
}

func newRTPState() (*rtpState, error) {
	var seed int64
	if err := binary.Read(rand.Reader, binary.BigEndian, &seed); err != nil {
		return nil, err
	}
	rng := mrand.New(mrand.NewSource(seed ^ time.Now().UnixNano()))
	return &rtpState{
		rng: rng,
	}, nil
}

func (r *rtpState) nextHeader(marker bool, padded bool) []byte {
	r.mu.Lock()
	defer r.mu.Unlock()

	header := make([]byte, rtpHeaderSize)
	header[0] = 0x80
	if padded {
		header[0] |= 0x20
	}
	pt := byte(rtpPayloadType)
	if marker {
		pt |= 0x80
	}
	header[1] = pt
	binary.BigEndian.PutUint16(header[2:4], uint16(r.rng.Uint32()))
	binary.BigEndian.PutUint32(header[4:8], r.rng.Uint32())
	binary.BigEndian.PutUint32(header[8:12], r.rng.Uint32())
	return header
}

func wrapRTP(rtp *rtpState, marker bool, payload []byte, padTo int) []byte {
	padded := false
	paddingLen := 0
	if padTo > len(payload) {
		paddingLen = padTo - len(payload)
		if paddingLen == 0 {
			paddingLen = 1
		}
		padded = true
	}
	header := rtp.nextHeader(marker, padded)
	packet := make([]byte, len(header)+len(payload)+paddingLen)
	copy(packet, header)
	copy(packet[len(header):], payload)
	if padded {
		if paddingLen > 1 {
			_, _ = io.ReadFull(rand.Reader, packet[len(header)+len(payload):len(packet)-1])
		}
		packet[len(packet)-1] = byte(paddingLen)
	}
	return packet
}

func unwrapRTP(packet []byte) ([]byte, error) {
	if len(packet) < rtpHeaderSize {
		return nil, errShortPacket
	}
	if packet[0]>>6 != 2 {
		return nil, errInvalidRTPVersion
	}
	cc := int(packet[0] & 0x0f)
	offset := rtpHeaderSize + cc*4
	if len(packet) < offset {
		return nil, errShortPacket
	}
	payload := packet[offset:]
	if packet[0]&0x20 != 0 {
		if len(payload) == 0 {
			return nil, errShortPacket
		}
		paddingLen := int(payload[len(payload)-1])
		if paddingLen == 0 || paddingLen > len(payload) {
			return nil, errShortPacket
		}
		payload = payload[:len(payload)-paddingLen]
	}
	return payload, nil
}

func generateTunnelID() (uint64, error) {
	var id uint64
	if err := binary.Read(rand.Reader, binary.BigEndian, &id); err != nil {
		return 0, err
	}
	if id == 0 {
		id = 1
	}
	return id, nil
}

func generateKeyPair() ([]byte, []byte, error) {
	priv, x, y, err := elliptic.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return priv, elliptic.Marshal(elliptic.P256(), x, y), nil
}

func deriveSharedSecret(priv, peerPub []byte) ([]byte, error) {
	x, y := elliptic.Unmarshal(elliptic.P256(), peerPub)
	if x == nil || y == nil {
		return nil, errInvalidHandshake
	}
	sharedX, _ := elliptic.P256().ScalarMult(x, y, priv)
	if sharedX == nil {
		return nil, errInvalidHandshake
	}
	raw := sharedX.Bytes()
	secret := make([]byte, 32)
	copy(secret[32-len(raw):], raw)
	return secret, nil
}

func deriveSessionKeys(secret []byte, clientSalt, serverSalt [16]byte) (clientKey, serverKey []byte, clientNonce, serverNonce [4]byte, err error) {
	info := []byte("rtp-proxy-v1")
	salt := append(clientSalt[:], serverSalt[:]...)
	keyMaterial := hkdfSHA256(secret, salt, info, 72)
	clientKey = append([]byte(nil), keyMaterial[:32]...)
	serverKey = append([]byte(nil), keyMaterial[32:64]...)
	copy(clientNonce[:], keyMaterial[64:68])
	copy(serverNonce[:], keyMaterial[68:72])
	return clientKey, serverKey, clientNonce, serverNonce, nil
}

func hkdfSHA256(secret, salt, info []byte, length int) []byte {
	extract := hmac.New(sha256.New, salt)
	_, _ = extract.Write(secret)
	prk := extract.Sum(nil)

	var result []byte
	var previous []byte
	counter := byte(1)
	for len(result) < length {
		expand := hmac.New(sha256.New, prk)
		if len(previous) > 0 {
			_, _ = expand.Write(previous)
		}
		_, _ = expand.Write(info)
		_, _ = expand.Write([]byte{counter})
		previous = expand.Sum(nil)
		result = append(result, previous...)
		counter++
	}
	return result[:length]
}

func makeNonce(prefix [4]byte, packetNum uint64) []byte {
	nonce := make([]byte, 12)
	copy(nonce[:4], prefix[:])
	binary.BigEndian.PutUint64(nonce[4:], packetNum)
	return nonce
}

func encodeHello(wireType byte, pkt helloPacket) []byte {
	payload := make([]byte, 1+1+8+16+1+len(pkt.Public))
	payload[0] = wireType
	payload[1] = protocolVersion
	binary.BigEndian.PutUint64(payload[2:10], pkt.TunnelID)
	copy(payload[10:26], pkt.Salt[:])
	payload[26] = byte(len(pkt.Public))
	copy(payload[27:], pkt.Public)
	return payload
}

func decodeHello(payload []byte) (helloPacket, error) {
	var pkt helloPacket
	if len(payload) < 27 {
		return pkt, errInvalidHandshake
	}
	if payload[1] != protocolVersion {
		return pkt, errInvalidVersion
	}
	pubLen := int(payload[26])
	if pubLen == 0 || len(payload) < 27+pubLen {
		return pkt, errInvalidHandshake
	}
	pkt.TunnelID = binary.BigEndian.Uint64(payload[2:10])
	copy(pkt.Salt[:], payload[10:26])
	pkt.Public = append([]byte(nil), payload[27:27+pubLen]...)
	return pkt, nil
}

func encodeEncryptedFrame(ack, ackBits uint64, frameType byte, framePayload []byte, minSize int) []byte {
	payload := make([]byte, 1+8+8+1+2+len(framePayload))
	payload[0] = protocolVersion
	binary.BigEndian.PutUint64(payload[1:9], ack)
	binary.BigEndian.PutUint64(payload[9:17], ackBits)
	payload[17] = frameType
	binary.BigEndian.PutUint16(payload[18:20], uint16(len(framePayload)))
	copy(payload[20:], framePayload)
	if minSize > len(payload) {
		padded := make([]byte, minSize)
		copy(padded, payload)
		if _, err := io.ReadFull(rand.Reader, padded[len(payload):]); err == nil {
			return padded
		}
		return payload
	}
	return payload
}

func decodeEncryptedFrame(plain []byte) (frameHeader, []byte, error) {
	var hdr frameHeader
	if len(plain) < 20 {
		return hdr, nil, errInvalidFrame
	}
	if plain[0] != protocolVersion {
		return hdr, nil, errInvalidVersion
	}
	hdr.Ack = binary.BigEndian.Uint64(plain[1:9])
	hdr.AckBits = binary.BigEndian.Uint64(plain[9:17])
	hdr.FrameType = plain[17]
	payloadLen := int(binary.BigEndian.Uint16(plain[18:20]))
	if len(plain) < 20+payloadLen {
		return hdr, nil, errInvalidFrame
	}
	return hdr, plain[20 : 20+payloadLen], nil
}

func encodeDataPayload(tunnelID, packetNum uint64, ciphertext []byte) []byte {
	payload := make([]byte, 1+8+8+len(ciphertext))
	payload[0] = wireTypeData
	binary.BigEndian.PutUint64(payload[1:9], tunnelID)
	binary.BigEndian.PutUint64(payload[9:17], packetNum)
	copy(payload[17:], ciphertext)
	return payload
}

func decodeDataPayload(payload []byte) (tunnelID, packetNum uint64, ciphertext []byte, err error) {
	if len(payload) < 17 || payload[0] != wireTypeData {
		return 0, 0, nil, errShortPacket
	}
	tunnelID = binary.BigEndian.Uint64(payload[1:9])
	packetNum = binary.BigEndian.Uint64(payload[9:17])
	ciphertext = payload[17:]
	return tunnelID, packetNum, ciphertext, nil
}

func encryptFrame(aead cipher.AEAD, noncePrefix [4]byte, packetNum uint64, ack, ackBits uint64, frameType byte, framePayload []byte, tunnelID uint64, minPlainSize int) []byte {
	plain := encodeEncryptedFrame(ack, ackBits, frameType, framePayload, minPlainSize)
	nonce := makeNonce(noncePrefix, packetNum)
	aad := make([]byte, 1+8+8)
	aad[0] = wireTypeData
	binary.BigEndian.PutUint64(aad[1:9], tunnelID)
	binary.BigEndian.PutUint64(aad[9:17], packetNum)
	return aead.Seal(nil, nonce, plain, aad)
}

func decryptFrame(aead cipher.AEAD, noncePrefix [4]byte, tunnelID, packetNum uint64, ciphertext []byte) (frameHeader, []byte, error) {
	var zero frameHeader
	nonce := makeNonce(noncePrefix, packetNum)
	aad := make([]byte, 1+8+8)
	aad[0] = wireTypeData
	binary.BigEndian.PutUint64(aad[1:9], tunnelID)
	binary.BigEndian.PutUint64(aad[9:17], packetNum)
	plain, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return zero, nil, err
	}
	return decodeEncryptedFrame(plain)
}

func randomSalt() ([16]byte, error) {
	var salt [16]byte
	_, err := io.ReadFull(rand.Reader, salt[:])
	return salt, err
}

func encodeOpenFrame(streamID uint32, host string, port uint16) []byte {
	hostBytes := []byte(host)
	payload := make([]byte, 4+2+2+len(hostBytes))
	binary.BigEndian.PutUint32(payload[0:4], streamID)
	binary.BigEndian.PutUint16(payload[4:6], port)
	binary.BigEndian.PutUint16(payload[6:8], uint16(len(hostBytes)))
	copy(payload[8:], hostBytes)
	return payload
}

func decodeOpenFrame(payload []byte) (streamID uint32, host string, port uint16, err error) {
	if len(payload) < 8 {
		return 0, "", 0, errInvalidFrame
	}
	streamID = binary.BigEndian.Uint32(payload[0:4])
	port = binary.BigEndian.Uint16(payload[4:6])
	hostLen := int(binary.BigEndian.Uint16(payload[6:8]))
	if len(payload) != 8+hostLen {
		return 0, "", 0, errInvalidFrame
	}
	host = string(payload[8:])
	return streamID, host, port, nil
}

func encodeOpenResultFrame(streamID uint32, ok bool, message string) []byte {
	msgBytes := []byte(message)
	payload := make([]byte, 4+1+2+len(msgBytes))
	binary.BigEndian.PutUint32(payload[0:4], streamID)
	if ok {
		payload[4] = 1
	}
	binary.BigEndian.PutUint16(payload[5:7], uint16(len(msgBytes)))
	copy(payload[7:], msgBytes)
	return payload
}

func decodeOpenResultFrame(payload []byte) (streamID uint32, ok bool, message string, err error) {
	if len(payload) < 7 {
		return 0, false, "", errInvalidFrame
	}
	streamID = binary.BigEndian.Uint32(payload[0:4])
	ok = payload[4] == 1
	msgLen := int(binary.BigEndian.Uint16(payload[5:7]))
	if len(payload) != 7+msgLen {
		return 0, false, "", errInvalidFrame
	}
	message = string(payload[7:])
	return streamID, ok, message, nil
}

func encodeStreamDataFrame(streamID uint32, offset uint64, data []byte) []byte {
	payload := make([]byte, 4+8+len(data))
	binary.BigEndian.PutUint32(payload[0:4], streamID)
	binary.BigEndian.PutUint64(payload[4:12], offset)
	copy(payload[12:], data)
	return payload
}

func decodeStreamDataFrame(payload []byte) (streamID uint32, offset uint64, data []byte, err error) {
	if len(payload) < 12 {
		return 0, 0, nil, errInvalidFrame
	}
	streamID = binary.BigEndian.Uint32(payload[0:4])
	offset = binary.BigEndian.Uint64(payload[4:12])
	data = append([]byte(nil), payload[12:]...)
	return streamID, offset, data, nil
}

func encodeEOFFrame(streamID uint32, finalOffset uint64) []byte {
	payload := make([]byte, 4+8)
	binary.BigEndian.PutUint32(payload[0:4], streamID)
	binary.BigEndian.PutUint64(payload[4:12], finalOffset)
	return payload
}

func decodeEOFFrame(payload []byte) (streamID uint32, finalOffset uint64, err error) {
	if len(payload) != 12 {
		return 0, 0, errInvalidFrame
	}
	streamID = binary.BigEndian.Uint32(payload[0:4])
	finalOffset = binary.BigEndian.Uint64(payload[4:12])
	return streamID, finalOffset, nil
}

func encodeResetFrame(streamID uint32, code byte, message string) []byte {
	msgBytes := []byte(message)
	payload := make([]byte, 4+1+2+len(msgBytes))
	binary.BigEndian.PutUint32(payload[0:4], streamID)
	payload[4] = code
	binary.BigEndian.PutUint16(payload[5:7], uint16(len(msgBytes)))
	copy(payload[7:], msgBytes)
	return payload
}

func decodeResetFrame(payload []byte) (streamID uint32, code byte, message string, err error) {
	if len(payload) < 7 {
		return 0, 0, "", errInvalidFrame
	}
	streamID = binary.BigEndian.Uint32(payload[0:4])
	code = payload[4]
	msgLen := int(binary.BigEndian.Uint16(payload[5:7]))
	if len(payload) != 7+msgLen {
		return 0, 0, "", errInvalidFrame
	}
	message = string(payload[7:])
	return streamID, code, message, nil
}

func encodeUDPPacketFrame(assocID uint32, datagramID uint32, host string, port uint16, data []byte) []byte {
	hostBytes := []byte(host)
	payload := make([]byte, 4+4+2+len(hostBytes)+2+2+len(data))
	binary.BigEndian.PutUint32(payload[0:4], assocID)
	binary.BigEndian.PutUint32(payload[4:8], datagramID)
	binary.BigEndian.PutUint16(payload[8:10], uint16(len(hostBytes)))
	copy(payload[10:10+len(hostBytes)], hostBytes)
	offset := 10 + len(hostBytes)
	binary.BigEndian.PutUint16(payload[offset:offset+2], port)
	binary.BigEndian.PutUint16(payload[offset+2:offset+4], uint16(len(data)))
	copy(payload[offset+4:], data)
	return payload
}

func decodeUDPPacketFrame(payload []byte) (assocID uint32, datagramID uint32, host string, port uint16, data []byte, err error) {
	if len(payload) < 14 {
		return 0, 0, "", 0, nil, errInvalidFrame
	}
	assocID = binary.BigEndian.Uint32(payload[0:4])
	datagramID = binary.BigEndian.Uint32(payload[4:8])
	hostLen := int(binary.BigEndian.Uint16(payload[8:10]))
	if len(payload) < 10+hostLen+4 {
		return 0, 0, "", 0, nil, errInvalidFrame
	}
	host = string(payload[10 : 10+hostLen])
	offset := 10 + hostLen
	port = binary.BigEndian.Uint16(payload[offset : offset+2])
	dataLen := int(binary.BigEndian.Uint16(payload[offset+2 : offset+4]))
	if len(payload) != offset+4+dataLen {
		return 0, 0, "", 0, nil, errInvalidFrame
	}
	data = append([]byte(nil), payload[offset+4:]...)
	return assocID, datagramID, host, port, data, nil
}

func encodeUDPCloseFrame(assocID uint32) []byte {
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload[:4], assocID)
	return payload
}

func decodeUDPCloseFrame(payload []byte) (uint32, error) {
	if len(payload) != 4 {
		return 0, errInvalidFrame
	}
	return binary.BigEndian.Uint32(payload[:4]), nil
}

func packetAcked(packetNum, ack, ackBits uint64) bool {
	if packetNum == 0 || ack == 0 {
		return false
	}
	if packetNum == ack {
		return true
	}
	if packetNum > ack {
		return false
	}
	diff := ack - packetNum
	if diff > 64 {
		return false
	}
	return ackBits&(uint64(1)<<(diff-1)) != 0
}

type recvTracker struct {
	largest uint64
	bits    uint64
}

func (r *recvTracker) mark(packetNum uint64) bool {
	if packetNum == 0 {
		return false
	}
	if r.largest == 0 {
		r.largest = packetNum
		r.bits = 0
		return true
	}
	if packetNum > r.largest {
		delta := packetNum - r.largest
		if delta >= 64 {
			r.bits = 0
		} else {
			r.bits <<= delta
			r.bits |= uint64(1) << (delta - 1)
		}
		r.largest = packetNum
		return true
	}
	if packetNum == r.largest {
		return false
	}
	diff := r.largest - packetNum
	if diff > 64 {
		return false
	}
	mask := uint64(1) << (diff - 1)
	already := r.bits&mask != 0
	r.bits |= mask
	return !already
}

func (r *recvTracker) snapshot() (uint64, uint64) {
	return r.largest, r.bits
}

func mustRandomUint32() uint32 {
	var v uint32
	if err := binary.Read(rand.Reader, binary.BigEndian, &v); err != nil {
		return uint32(time.Now().UnixNano() & math.MaxUint32)
	}
	return v
}

func joinHostPort(host string, port uint16) string {
	return net.JoinHostPort(host, fmt.Sprintf("%d", port))
}
