package transport

import (
	"errors"
	"fmt"
	"io"
	"net"
)

const (
	HeaderLen     = 4
	MaxMessageLen = 16 << 20
)

var ErrFrameTooLarge = errors.New("transport: frame exceeds maximum length")

func readUint24(b []byte) uint32 {
	return uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2])
}

func writeUint24(b []byte, v uint32) {
	b[0] = byte(v >> 16)
	b[1] = byte(v >> 8)
	b[2] = byte(v)
}

type FramedConn struct {
	r       io.Reader
	w       io.Writer
	rawConn net.Conn
	readBuf []byte
	hdrBuf  [HeaderLen]byte
	// 首帧里夹着 SMB1 多协议协商的话只换一次，后续帧一律原样通过。
	firstFrame bool
}

func NewFramedConn(c net.Conn) *FramedConn {
	fc := &FramedConn{r: c, w: c, rawConn: c, firstFrame: true}
	readBuf := make([]byte, 0, 64<<10)
	fc.readBuf = readBuf[:0]
	return fc
}

// ReadMessage 读一帧。首帧如果是 SMB1 NEGOTIATE，换成 SMB2 NEGOTIATE 请求再交出去：
// 未关 SMB1 的 Windows/WinPE 客户端会先发这一帧，不换它就死在 bad protocol id 上。
func (f *FramedConn) ReadMessage() ([]byte, error) {
	msg, err := f.readFrame()
	if err != nil {
		return nil, err
	}
	if f.firstFrame {
		f.firstFrame = false
		if upgraded, ok := upgradeSMB1Negotiate(msg); ok {
			return upgraded, nil
		}
	}
	return msg, nil
}

func (f *FramedConn) readFrame() ([]byte, error) {
	if _, err := io.ReadFull(f.r, f.hdrBuf[:]); err != nil {
		return nil, fmt.Errorf("transport: read frame header: %w", err)
	}
	if f.hdrBuf[0] != 0x00 {
		return nil, fmt.Errorf("transport: unexpected frame type byte 0x%02x", f.hdrBuf[0])
	}
	n := int(readUint24(f.hdrBuf[1:]))
	if n == 0 {
		f.readBuf = f.readBuf[:0]
		return f.readBuf, nil
	}
	if n > MaxMessageLen {
		return nil, fmt.Errorf("%w: %d bytes", ErrFrameTooLarge, n)
	}
	if cap(f.readBuf) < n {
		f.readBuf = make([]byte, n)
	} else {
		f.readBuf = f.readBuf[:n]
	}
	if _, err := io.ReadFull(f.r, f.readBuf); err != nil {
		return nil, fmt.Errorf("transport: read frame body: %w", err)
	}
	return f.readBuf, nil
}

func (f *FramedConn) WriteMessage(payload []byte) error {
	if len(payload) == 0 {
		return errors.New("transport: cannot write empty frame")
	}
	if uint32(len(payload)) > MaxMessageLen {
		return fmt.Errorf("%w: %d bytes", ErrFrameTooLarge, len(payload))
	}
	f.hdrBuf[0] = 0x00
	writeUint24(f.hdrBuf[1:], uint32(len(payload)))

	if _, err := f.w.Write(f.hdrBuf[:]); err != nil {
		return fmt.Errorf("transport: write frame header: %w", err)
	}
	if _, err := f.w.Write(payload); err != nil {
		return fmt.Errorf("transport: write frame body: %w", err)
	}
	return nil
}

func (f *FramedConn) Underlying() net.Conn { return f.rawConn }

func ReadFrame(r io.Reader, buf *[]byte) ([]byte, error) {
	var hdr [HeaderLen]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, fmt.Errorf("transport: read frame header: %w", err)
	}
	if hdr[0] != 0x00 {
		return nil, fmt.Errorf("transport: unexpected frame type byte 0x%02x", hdr[0])
	}
	n := int(readUint24(hdr[1:]))
	if n == 0 {
		*buf = (*buf)[:0]
		return *buf, nil
	}
	if n > MaxMessageLen {
		return nil, fmt.Errorf("%w: %d bytes", ErrFrameTooLarge, n)
	}
	if cap(*buf) < n {
		*buf = make([]byte, n)
	} else {
		*buf = (*buf)[:n]
	}
	if _, err := io.ReadFull(r, *buf); err != nil {
		return nil, fmt.Errorf("transport: read frame body (%d bytes): %w", n, err)
	}
	return *buf, nil
}

func WriteFrame(w io.Writer, payload []byte) error {
	if len(payload) == 0 {
		return errors.New("transport: cannot write empty frame")
	}
	if uint32(len(payload)) > MaxMessageLen {
		return fmt.Errorf("%w: %d bytes", ErrFrameTooLarge, len(payload))
	}
	var hdr [HeaderLen]byte
	hdr[0] = 0x00
	writeUint24(hdr[1:], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return fmt.Errorf("transport: write frame header: %w", err)
	}
	if _, err := w.Write(payload); err != nil {
		return fmt.Errorf("transport: write frame body: %w", err)
	}
	return nil
}
