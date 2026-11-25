package transport

import (
	"encoding/binary"
	"fmt"
	"os"
)

// SMB1 多协议协商的垫片。
//
// Windows 客户端在「SMB1 客户端仍然启用」时会先发一个 SMB1 NEGOTIATE，方言表里
// 夹带 SMB2 的标记（0x02FF「SMB 2.???」之类），意思是「我也会 SMB2/3，你挑一个」。
// 真正的 Windows 服务器会把它当成 SMB2 协商来回答。本库只认 \xFE SMB 的帧，
// 于是这种客户端在第一个包上就被判成 "wire: bad protocol id" 并断开，
// WinPE / 未关 SMB1 的机器表现为「无法连接」。
//
// 处理方式：把这一帧整个换成一个等价的 SMB2 NEGOTIATE 请求交回正常流程，
// 让库自己挑方言、发响应。
//
// 方言清单必须从 SMB1 的 body 里读出来：Windows 只接受它自己列过的方言，
// 报一个它没列的（例如对着 Win7 内核的 PE 报 3.0.2）会直接被它掉头关连接。
// goshs（smbserver/server.go:412）与 macos-fuse-t/go-smb2（server/server.go:649）
// 都不读这一段，直接报最高方言——对它们够用，对老 PE 不够。

const (
	smb1ProtocolID   = "\xffSMB"
	smb1CmdNegotiate = 0x72

	// SMB1 NEGOTIATE 请求的固定偏移：头 32 字节，WordCount 必为 0，
	// 随后是 ByteCount（WORD）和方言清单（每个方言一个 WORD）。
	smb1HeaderLen   = 32
	smb1DialectsOff = 35
	// 「SMB 2.???」通配：客户端说「SMB2/3 随你挑多高的」。
	smb1WildcardSMB2 = 0x02FF

	// SMB2 头部与 NEGOTIATE 请求体的固定长度。
	smb2HeaderLen    = 64
	smb2NegotBody    = 36
	smb2CmdNegotiate = 0

	// 只报这些方言：库里最高的就是 3.0.2，报 3.1.1 需要协商上下文。
	dialect202 = 0x0202
	dialect210 = 0x0210
	dialect300 = 0x0300
	dialect302 = 0x0302
)

// isSMB1Negotiate 判断这一帧是不是 SMB1 的 NEGOTIATE 请求。
func isSMB1Negotiate(msg []byte) bool {
	return len(msg) > 8 && string(msg[0:4]) == smb1ProtocolID && msg[4] == smb1CmdNegotiate
}

// upgradeSMB1Negotiate 把 SMB1 NEGOTIATE 换成 SMB2 NEGOTIATE 请求。
// 第二项为 false 表示这一帧不需要替换，调用方原样往下走。
func upgradeSMB1Negotiate(msg []byte) ([]byte, bool) {
	if !isSMB1Negotiate(msg) {
		return nil, false
	}
	dialects := smb1SMB2Dialects(msg)
	if len(dialects) == 0 {
		// 只列了 SMB1 方言：这种客户端本来就不是 SMB2 的活儿，别硬装。
		return nil, false
	}
	if debugSMB1() {
		fmt.Fprintf(os.Stderr, "[smb1] 客户端声明 % x → 提交 % x\n", smb1DeclaredDialects(msg), dialects)
	}
	return buildSMB2Negotiate(dialects), true
}

// smb1SMB2Dialects 挑出客户端声明过的 SMB2 方言，按升序去重。
// 「SMB 2.???」通配展开成整条阶梯。返回 nil 表示它没说 SMB2。
func smb1SMB2Dialects(msg []byte) []uint16 {
	var out []uint16
	for _, w := range smb1DeclaredDialects(msg) {
		switch w {
		case dialect202, dialect210, dialect300, dialect302:
			out = appendDialect(out, w)
		case smb1WildcardSMB2:
			for _, d := range []uint16{dialect202, dialect210, dialect300, dialect302} {
				out = appendDialect(out, d)
			}
		}
	}
	return out
}

// smb1DeclaredDialects 读方言清单原文。结构不认得就返回 nil。
func smb1DeclaredDialects(msg []byte) []uint16 {
	if len(msg) < smb1DialectsOff || msg[smb1HeaderLen] != 0 {
		return nil
	}
	n := int(binary.LittleEndian.Uint16(msg[smb1HeaderLen+1:]))
	if n < 2 || smb1DialectsOff+n > len(msg) {
		return nil
	}
	out := make([]uint16, 0, n/2)
	for i := 0; i+1 < n; i += 2 {
		out = append(out, binary.LittleEndian.Uint16(msg[smb1DialectsOff+i:]))
	}
	return out
}

func appendDialect(out []uint16, d uint16) []uint16 {
	for _, have := range out {
		if have == d {
			return out
		}
	}
	return append(out, d)
}

// smb1ParseReport 把首帧的解析结果说清楚，只在 SMBDEMO_DEBUG_SMB1 打开时用。
func smb1ParseReport(msg []byte) string {
	if len(msg) < 4 {
		return fmt.Sprintf("  只有 %d 字节，连协议标记都没有\n", len(msg))
	}
	proto := ""
	switch string(msg[0:4]) {
	case smb1ProtocolID:
		proto = "SMB1"
	case "\xfeSMB":
		proto = "SMB2（原生的，垫片不管）"
	default:
		proto = fmt.Sprintf("不认识的 % x", msg[0:4])
	}
	if proto != "SMB1" {
		return "  协议：" + proto + "\n"
	}
	if len(msg) < smb1DialectsOff {
		return fmt.Sprintf("  协议：SMB1，但只有 %d 字节，读不到方言表\n", len(msg))
	}
	wc := msg[smb1HeaderLen]
	bc := int(binary.LittleEndian.Uint16(msg[smb1HeaderLen+1:]))
	return fmt.Sprintf("  协议：SMB1，cmd=0x%02x，WordCount=%d，ByteCount=%d，声明的方言 % x\n",
		msg[4], wc, bc, smb1DeclaredDialects(msg))
}

// debugSMB1 打开后把客户端声明的方言打到 stderr，现场排查用（默认关）。
func debugSMB1() bool { return os.Getenv("SMBDEMO_DEBUG_SMB1") != "" }

// buildSMB2Negotiate 造一个最小但合法的 SMB2 NEGOTIATE 请求。
//
// 头部（64 字节）：protocol + StructureSize=64 + CreditCharge=1 + Command=0 +
// CreditRequest=1，其余为 0（MessageId/SessionId 在协商阶段就是 0）。
// 请求体（36 字节）：StructureSize=36 + DialectCount + SecurityMode=1
// （允许签名，MS-SMB2 §3.2.5.2 说缺这一位 Windows 应当拒绝）+ 方言表。
func buildSMB2Negotiate(dialects []uint16) []byte {
	buf := make([]byte, smb2HeaderLen+smb2NegotBody+2*len(dialects))

	buf[0], buf[1], buf[2], buf[3] = 0xFE, 'S', 'M', 'B'
	putU16(buf[4:], smb2HeaderLen)     // StructureSize
	putU16(buf[6:], 1)                 // CreditCharge
	putU16(buf[12:], smb2CmdNegotiate) // Command
	putU16(buf[14:], 1)                // CreditRequest

	body := buf[smb2HeaderLen:]
	putU16(body[0:], smb2NegotBody)
	putU16(body[2:], uint16(len(dialects))) // DialectCount
	putU16(body[4:], 0x0001)                // SecurityMode: signing enabled
	// Capabilities / ClientGuid / ClientStartTime 留 0。

	d := body[smb2NegotBody:]
	for i, dialect := range dialects {
		putU16(d[2*i:], dialect)
	}
	return buf
}

func putU16(b []byte, v uint16) {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
}
