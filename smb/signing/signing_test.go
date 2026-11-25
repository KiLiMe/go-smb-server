package signing

import (
	"bytes"
	"crypto/aes"
	"encoding/hex"
	"testing"
)

var (
	rfcKey, _ = hex.DecodeString("2b7e151628aed2a6abf7158809cf4f3c")
	rfcK1, _  = hex.DecodeString("fbeed618357133667c85e08f7236a8de")
	rfcK2, _  = hex.DecodeString("f7ddac306ae266ccf90bc11ee46d513b")

	emptyCMAC, _    = hex.DecodeString("bb1d6929e95937287fa37d129b756746")
	oneBlock, _     = hex.DecodeString("6bc1bee22e409f96e93d7e117393172a")
	oneBlockCMAC, _ = hex.DecodeString("070a16b46b4d4144f79bdd9dd04a287c")
)

func TestCMACSubkeys(t *testing.T) {
	b, err := aes.NewCipher(rfcKey)
	if err != nil {
		t.Fatal(err)
	}
	var l [16]byte
	b.Encrypt(l[:], l[:])
	k1 := cmacShift(l)
	k2 := cmacShift(k1)
	if !constantEqual(k1[:], rfcK1) {
		t.Fatalf("K1 = %x, want %x", k1, rfcK1)
	}
	if !constantEqual(k2[:], rfcK2) {
		t.Fatalf("K2 = %x, want %x", k2, rfcK2)
	}
}

func TestCMACEmptyMessage(t *testing.T) {
	s, err := NewSigner(rfcKey, AlgoAESCMAC)
	if err != nil {
		t.Fatal(err)
	}
	got := s.cmac(nil)
	if !constantEqual(got[:], emptyCMAC) {
		t.Fatalf("CMAC(\"\") = %x, want %x", got, emptyCMAC)
	}
}

func TestCMACOneBlock(t *testing.T) {
	s, err := NewSigner(rfcKey, AlgoAESCMAC)
	if err != nil {
		t.Fatal(err)
	}
	got := s.cmac(oneBlock)
	if !constantEqual(got[:], oneBlockCMAC) {
		t.Fatalf("CMAC(1 block) = %x, want %x", got, oneBlockCMAC)
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	msg := make([]byte, 68)
	copy(msg[0:4], []byte{0xFE, 'S', 'M', 'B'})
	key := []byte("0123456789abcdef")

	if err := Sign(msg, key, AlgoAESCMAC); err != nil {
		t.Fatal(err)
	}
	if isZero(msg[48:64]) {
		t.Fatal("signature not written")
	}

	saved := make([]byte, len(msg))
	copy(saved, msg)
	msg[65] ^= 0xFF
	ok, err := Verify(msg, key, AlgoAESCMAC)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("verify accepted a tampered message")
	}

	copy(msg, saved)
	ok, err = Verify(msg, key, AlgoAESCMAC)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("verify rejected a valid message")
	}
}

func isZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

// 验签时 msg[48:64] 里躺着对端的签名：必须先当零再算，否则永远不匹配。
func TestVerifyIgnoresSignatureField(t *testing.T) {
	key := []byte("0123456789abcdef")
	for _, algo := range []Algorithm{AlgoHMACSHA256, AlgoAESCMAC} {
		msg := make([]byte, 64+8)
		copy(msg[0:4], "\xfeSMB")
		copy(msg[64:], "payload!")
		// 先按零签名，然后把签名写进去——这正是线上收到的样子。
		if err := Sign(msg, key, algo); err != nil {
			t.Fatalf("%v: %v", algo, err)
		}
		signed := append([]byte(nil), msg...)
		ok, err := Verify(signed, key, algo)
		if err != nil || !ok {
			t.Errorf("algo=0x%04x：自己的签名验不过（ok=%v err=%v）", algo, ok, err)
		}
		// 再来一次：字段里已有签名时重新签名，结果必须与第一次相同。
		if err := Sign(signed, key, algo); err != nil {
			t.Fatalf("%v: %v", algo, err)
		}
		if !bytes.Equal(msg[48:64], signed[48:64]) {
			t.Errorf("algo=0x%04x：签名随字段里的旧值变了", algo)
		}
	}
}
