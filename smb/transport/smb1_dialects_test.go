package transport

import (
	"reflect"
	"testing"
)

// 客户端列了什么，就只提交什么：Windows 拒绝没列过的方言。
func TestDialectsFollowClient(t *testing.T) {
	cases := []struct {
		name   string
		listed []uint16
		want   []uint16
	}{
		{"Win7 内核的 PE（最高 2.1）", []uint16{0x0006, 0x0202, 0x0210}, []uint16{0x0202, 0x0210}},
		{"现代 PE（通配）", []uint16{0x0006, 0x02FF}, []uint16{0x0202, 0x0210, 0x0300, 0x0302}},
		{"显式 3.0.2", []uint16{0x0006, 0x0302}, []uint16{0x0302}},
		{"只说 SMB1", []uint16{0x0006}, nil},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			got := smb1SMB2Dialects(smb1Negotiate(c.listed...))
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("得到 %x，想要 %x", got, c.want)
			}
			upgraded, ok := upgradeSMB1Negotiate(smb1Negotiate(c.listed...))
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
