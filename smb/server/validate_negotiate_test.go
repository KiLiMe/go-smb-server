package server

import (
	"encoding/binary"
	"testing"

	"github.com/sonroyaalmerol/go-smb-server/smb/wire"
)

// 响应必须是 24 字节：Capabilities(4) + Guid(16) + SecurityMode(1) + 保留(1) + Dialect(2)。
// 没有 DialectCount——客户端（Samba 的 smb2cli_validate_negotiate_info_recv）要求
// output 长度正好 24，多一个字节就判 INVALID_NETWORK_RESPONSE。
func TestValidateNegotiateInfoIs24Bytes(t *testing.T) {
	var guid [16]byte
	for i := range guid {
		guid[i] = byte(i + 1)
	}
	got := buildValidateNegotiateInfo(wire.DialectSMB302, guid)

	if len(got) != 24 {
		t.Fatalf("长度 %d，想要 24", len(got))
	}
	if c := binary.LittleEndian.Uint32(got[0:4]); c != wire.CapLargeMTU {
		t.Errorf("Capabilities = 0x%08x，想要 0x%08x", c, wire.CapLargeMTU)
	}
	if g := [16]byte(got[4:20]); g != guid {
		t.Errorf("Guid = %x，想要 %x", g, guid)
	}
	if m := got[20]; m != byte(wire.SigningEnabled) {
		t.Errorf("SecurityMode = %d，想要 %d", m, wire.SigningEnabled)
	}
	if b := got[21]; b != 0 {
		t.Errorf("保留字节 = %d，想要 0", b)
	}
	if d := binary.LittleEndian.Uint16(got[22:24]); d != wire.DialectSMB302 {
		t.Errorf("Dialect = 0x%04x，想要 0x%04x", d, wire.DialectSMB302)
	}
}
