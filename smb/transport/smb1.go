package transport

// SMB1 多协议协商的垫片。
//
// Windows 客户端在「SMB1 客户端仍然启用」时会先发一个 SMB1 NEGOTIATE，方言表里
// 夹带 SMB2 的标记（0x02FF「SMB 2.???」之类），意思是「我也会 SMB2/3，你挑一个」。
// 真正的 Windows 服务器会把它当成 SMB2 协商来回答。本库只认 \xFE SMB 的帧，
// 于是这种客户端在第一个包上就被判成 "wire: bad protocol id" 并断开，
// WinPE / 未关 SMB1 的机器表现为「无法连接」。
//
// 处理方式：把这一帧整个换成一个等价的 SMB2 NEGOTIATE 请求交回正常流程，
// 让库自己挑方言、发响应。不解析 SMB1 的 body——方言表对结果没有影响，库里
// 已经有自己的方言阶梯，客户端拿到的响应是它认得的格式。同类做法可参照
// goshs 的 smbserver/server.go:412（MIT）与 macos-fuse-t/go-smb2 的
// server/server.go:649。

const (
	smb1ProtocolID   = "\xffSMB"
	smb1CmdNegotiate = 0x72

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
	return buildSMB2Negotiate(), true
}

// buildSMB2Negotiate 造一个最小但合法的 SMB2 NEGOTIATE 请求。
//
// 头部（64 字节）：protocol + StructureSize=64 + CreditCharge=1 + Command=0 +
// CreditRequest=1，其余为 0（MessageId/SessionId 在协商阶段就是 0）。
// 请求体（36 字节）：StructureSize=36 + DialectCount + SecurityMode=1
// （允许签名，MS-SMB2 §3.2.5.2 说缺这一位 Windows 应当拒绝）+ 方言表。
func buildSMB2Negotiate() []byte {
	dialects := []uint16{dialect202, dialect210, dialect300, dialect302}
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
