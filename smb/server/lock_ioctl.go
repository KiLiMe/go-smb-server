package server

import (
	"context"
	"encoding/binary"
	"sync"

	"github.com/sonroyaalmerol/go-smb-server/smb/vfs"
	"github.com/sonroyaalmerol/go-smb-server/smb/wire"
)

type lockRange struct {
	start, end uint64
	exclusive  bool
}

type lockManager struct {
	mu     sync.Mutex
	ranges []lockRange
}

type lockMgrSet struct {
	mu   sync.Mutex
	mgrs map[string]*lockManager
}

func newLockMgrSet() *lockMgrSet {
	return &lockMgrSet{mgrs: make(map[string]*lockManager)}
}

func (s *lockMgrSet) manager(path string) *lockManager {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.mgrs[path]
	if !ok {
		m = &lockManager{}
		s.mgrs[path] = m
	}
	return m
}

func (m *lockManager) conflicts(start, end uint64, exclusive bool) (int, bool) {
	for i, r := range m.ranges {
		overlap := start < r.end && r.start < end
		if overlap && (r.exclusive || exclusive) {
			return i, true
		}
	}
	return -1, false
}

func (m *lockManager) tryLock(start, length uint64, exclusive, failImmediately bool) bool {
	end := start + length
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, conflict := m.conflicts(start, end, exclusive); conflict {
		if failImmediately {
			return false
		}
		return false
	}
	m.ranges = append(m.ranges, lockRange{start: start, end: end, exclusive: exclusive})
	return true
}

func (m *lockManager) unlock(start, length uint64) {
	end := start + length
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, r := range m.ranges {
		if r.start == start && r.end == end {
			m.ranges = append(m.ranges[:i], m.ranges[i+1:]...)
			return
		}
	}
}

func (c *conn) handleLock(_ context.Context, msg []byte, tr *tree) uint32 {
	var req wire.LockRequest
	if err := req.Parse(msg); err != nil {
		return c.errBody(wire.StatusInvalidParameter)
	}
	oh, ok := tr.opens[req.FileId]
	if !ok {
		return c.errBody(wire.StatusInvalidHandle)
	}
	lm := tr.locks.manager(oh.path)
	for _, l := range req.Locks {
		switch {
		case l.Flags&wire.LockFlagUnlock != 0:
			lm.unlock(l.Offset, l.Length)
		case l.Flags&wire.LockFlagExclusiveLock != 0:
			if !lm.tryLock(l.Offset, l.Length, true, l.Flags&wire.LockFlagFailImmediately != 0) {
				return c.errBody(wire.StatusLockConflict)
			}
		case l.Flags&wire.LockFlagSharedLock != 0:
			if !lm.tryLock(l.Offset, l.Length, false, l.Flags&wire.LockFlagFailImmediately != 0) {
				return c.errBody(wire.StatusLockConflict)
			}
		default:
			return c.errBody(wire.StatusInvalidParameter)
		}
	}
	c.out = wire.LockResponseAppend(c.out)
	return wire.StatusSuccess
}

func (c *conn) handleIoctl(ctx context.Context, msg []byte, tr *tree) uint32 {
	var req wire.IoctlRequest
	if err := req.Parse(msg); err != nil {
		return c.errBody(wire.StatusInvalidParameter)
	}
	switch req.CtlCode {
	case wire.FSCTLValidateNegotiateInfo:
		resp := buildValidateNegotiateInfo(c.dialect, c.srv.guid)
		c.out = wire.IoctlResponseAppend(c.out, req.CtlCode, req.FileId, nil, resp, req.Flags)
		return wire.StatusSuccess
	case wire.FSCTLQueryNetworkInterfaceInfo:
		c.out = wire.IoctlResponseAppend(c.out, req.CtlCode, req.FileId, nil, nil, req.Flags)
		return wire.StatusSuccess
	case wire.FSCTLPipeWait:
		c.out = wire.IoctlResponseAppend(c.out, req.CtlCode, req.FileId, nil, nil, req.Flags)
		return wire.StatusSuccess
	case wire.FSCTLPipeTransceive:
		if tr != nil {
			if oh, ok := tr.opens[req.FileId]; ok {
				if pp, ok2 := oh.h.(vfs.PipeProcessor); ok2 {
					result := pp.ProcessPipe(ctx, req.Input)
					c.out = wire.IoctlResponseAppend(c.out, req.CtlCode, req.FileId, nil, result, req.Flags)
					return wire.StatusSuccess
				}
			}
		}
		return c.errBody(wire.StatusNotSupported)
	default:
		if tr == nil {
			return c.errBody(wire.StatusInvalidDeviceRequest)
		}
		if _, ok := tr.opens[req.FileId]; !ok {
			return c.errBody(wire.StatusInvalidHandle)
		}
		return c.errBody(wire.StatusNotSupported)
	}
}

// buildValidateNegotiateInfo 组 VALIDATE_NEGOTIATE_INFO 的响应：**必须是 24 字节**，
// Capabilities(4) + Guid(16) + SecurityMode(1) + 保留(1) + Dialect(2)。
//
// 这里没有 DialectCount、只回**协商选中的那一个**方言——和 2.2.32.2 的请求结构不同，
// 容易想当然。Samba 的校验（libcli/smb/smbXcli_base.c 的
// smb2cli_validate_negotiate_info_recv）依次要求：output 长度正好 24、
// capabilities/guid/security_mode 与协商响应一致、dialect 等于双方选中的那个；
// 任何一项不符都是 NT_STATUS_ACCESS_DENIED，而调用点（libcli/smb/smb2cli_tcon.c:301）
// 把它报成「tree connect failed」，看起来像树连接的问题。
//
// 原先发 26 字节（多了一个 DialectCount=1），长度就已经不对；Windows 更是直接丢连接。
func buildValidateNegotiateInfo(dialect uint16, guid [16]byte) []byte {
	out := make([]byte, 24)
	binary.LittleEndian.PutUint32(out[0:4], wire.CapLargeMTU)
	copy(out[4:20], guid[:])
	out[20] = byte(wire.SigningEnabled)
	out[21] = 0 // 保留，必须为 0
	binary.LittleEndian.PutUint16(out[22:24], dialect)
	return out
}
