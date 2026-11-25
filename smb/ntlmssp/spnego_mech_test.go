package ntlmssp

import (
	"encoding/hex"
	"testing"
)

func TestMechListTokenShape(t *testing.T) {
	tok := MechListToken()
	t.Logf("%d 字节: %s", len(tok), hex.EncodeToString(tok))
	if len(tok) == 0 || tok[0] != 0x60 {
		t.Fatalf("不是 InitialContextToken：%x", tok)
	}
	// 里面要有 NTLMSSP 的 OID（1.3.6.1.4.1.311.2.2.10）
	if !containsSub(tok, []byte{0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a}) {
		t.Error("缺 NTLMSSP OID")
	}
	if !containsSub(tok, []byte{0x2b, 0x06, 0x01, 0x05, 0x05, 0x02}) {
		t.Error("缺 SPNEGO OID")
	}
}

func containsSub(b, sub []byte) bool {
	for i := 0; i+len(sub) <= len(b); i++ {
		match := true
		for j := range sub {
			if b[i+j] != sub[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
