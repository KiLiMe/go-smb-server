package transport

import (
	"reflect"
	"testing"
)

// 客户端列了什么就只提交什么：Windows 拒绝它没列过的方言。
func TestDialectsFollowClient(t *testing.T) {
	cases := []struct {
		name   string
		listed []string
		want   []uint16
	}{
		// 现场那台 PE 的原样清单：通配符只承诺到 SMB2，没有 3.x 字样。
		{"WinPE 1912（实测清单）", []string{
			"PC NETWORK PROGRAM 1.0", "LANMAN1.0", "Windows for Workgroups 3.1a",
			"LM1.2X002", "LANMAN2.1", "NT LM 0.12", "SMB 2.002", "SMB 2.???",
		}, []uint16{0x0202, 0x0210}},
		{"显式 3.0.2 + 通配", []string{"NT LM 0.12", "SMB 2.002", "SMB 2.???", "SMB 3.02"},
			[]uint16{0x0202, 0x0210, 0x0300, 0x0302}},
		{"只有 2.002", []string{"NT LM 0.12", "SMB 2.002"}, []uint16{0x0202}},
		{"只说 SMB1", []string{"NT LM 0.12"}, nil},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			frame := smb1Negotiate(c.listed...)
			if got := smb1SMB2Dialects(frame); !reflect.DeepEqual(got, c.want) {
				t.Errorf("得到 %x，想要 %x", got, c.want)
			}
			upgraded, ok := upgradeSMB1Negotiate(frame)
			if (len(c.want) > 0) != ok {
				t.Fatalf("ok=%v，方言 %x", ok, c.want)
			}
			if ok {
				count := int(upgraded[64+2]) | int(upgraded[64+3])<<8
				if count != len(c.want) {
					t.Errorf("请求里 DialectCount=%d，想要 %d", count, len(c.want))
				}
			}
		})
	}
}
