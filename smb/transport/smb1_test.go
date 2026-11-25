package transport

import (
	"bytes"
	"io"
	"net"
	"testing"
)

// smb1Negotiate 造一个 SMB1 多协议协商请求（不带 4 字节帧头）。
//
// 头部的字段照 WinPE 实测的首包（flags2=0x5318、TID=0xFFFF、PID=0xFFFE）
// 构造；方言表是 <0x02><名字><NUL> 的字符串数组，不是 WORD 数组。
func smb1Negotiate(dialects ...string) []byte {
	hdr := make([]byte, 32)
	copy(hdr[0:4], "\xffSMB")
	hdr[4] = 0x72 // SMB_COM_NEGOTIATE
	hdr[10] = 0x18
	hdr[11] = 0x53 // flags2
	hdr[24], hdr[25] = 0xFF, 0xFF
	hdr[26], hdr[27] = 0xFF, 0xFE

	var list []byte
	for _, d := range dialects {
		list = append(list, 0x02)
		list = append(list, d...)
		list = append(list, 0)
	}
	body := []byte{0} // WordCount = 0
	body = append(body, byte(len(list)), byte(len(list)>>8))
	return append(append(hdr, body...), list...)
}

func frame(payload []byte) []byte {
	n := len(payload)
	return append([]byte{0x00, byte(n >> 16), byte(n >> 8), byte(n)}, payload...)
}

func TestUpgradeSMB1Negotiate(t *testing.T) {
	got, ok := upgradeSMB1Negotiate(smb1Negotiate("NT LM 0.12", "SMB 2.002", "SMB 2.???"))
	if !ok {
		t.Fatal("SMB1 NEGOTIATE 没有被认出来")
	}
	if !bytes.Equal(got[0:4], []byte{0xFE, 'S', 'M', 'B'}) {
		t.Fatalf("协议标记 %x，想要 fe 53 4d 42", got[0:4])
	}
	if cmd := uint16(got[12]) | uint16(got[13])<<8; cmd != 0 {
		t.Errorf("Command = %d，想要 0（NEGOTIATE）", cmd)
	}
	if ss := uint16(got[4]) | uint16(got[5])<<8; ss != smb2HeaderLen {
		t.Errorf("头部 StructureSize = %d，想要 64", ss)
	}

	body := got[smb2HeaderLen:]
	if ss := uint16(body[0]) | uint16(body[1])<<8; ss != smb2NegotBody {
		t.Errorf("请求体 StructureSize = %d，想要 36", ss)
	}
	count := int(uint16(body[2]) | uint16(body[3])<<8)
	if count != 2 {
		// 客户端只说「SMB 2.002」+「SMB 2.???」：通配符只承诺到 2.1。
		t.Fatalf("DialectCount = %d，想要 2", count)
	}
	if mode := uint16(body[4]) | uint16(body[5])<<8; mode&0x0001 == 0 {
		t.Error("SecurityMode 缺了 signing enabled（0x0001），Windows 应当拒绝")
	}
	want := []uint16{dialect202, dialect210}
	for i, w := range want {
		off := smb2NegotBody + 2*i
		if d := uint16(body[off]) | uint16(body[off+1])<<8; d != w {
			t.Errorf("方言[%d] = 0x%04x，想要 0x%04x", i, d, w)
		}
	}
	if len(got) != smb2HeaderLen+smb2NegotBody+2*len(want) {
		t.Errorf("长度 %d 不对", len(got))
	}
}

func TestUpgradeIgnoresOtherFrames(t *testing.T) {
	cases := map[string][]byte{
		"SMB2 协商": append([]byte{0xFE, 'S', 'M', 'B'}, make([]byte, 60)...),
		"太短":      []byte{0xFF, 'S', 'M'},
		"SMB1 非协商": func() []byte {
			b := smb1Negotiate("NT LM 0.12", "SMB 2.002", "SMB 2.???")
			b[4] = 0x73 // SESSION_SETUP
			return b
		}(),
	}
	for name, msg := range cases {
		if _, ok := upgradeSMB1Negotiate(msg); ok {
			t.Errorf("%s 不该被替换", name)
		}
	}
}

// 首帧换掉，第二帧原样通过：只换一次，否则重协商会被打乱。
func TestReadMessageUpgradesFirstFrameOnly(t *testing.T) {
	cli, srv := net.Pipe()
	t.Cleanup(func() { cli.Close(); srv.Close() })

	fc := NewFramedConn(srv)
	go func() {
		_, _ = cli.Write(frame(smb1Negotiate("NT LM 0.12", "SMB 2.002", "SMB 2.???")))
		_, _ = cli.Write(frame([]byte{0xFE, 'S', 'M', 'B', 9, 9, 9, 9}))
		cli.Close()
	}()

	first, err := fc.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first[0:4], []byte{0xFE, 'S', 'M', 'B'}) || len(first) == 8 {
		t.Fatalf("首帧应当被换成 SMB2 协商请求，实际 %x", first)
	}
	second, err := fc.ReadMessage()
	if err != nil && err != io.EOF {
		t.Fatal(err)
	}
	if !bytes.Equal(second, []byte{0xFE, 'S', 'M', 'B', 9, 9, 9, 9}) {
		t.Fatalf("第二帧不该被改动，实际 %x", second)
	}
}
