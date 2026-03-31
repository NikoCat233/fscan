package Plugins

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"io"
	"math/rand"
	"net"
	"os"
	"strings"
	"time"
)

const (
	nfsProgram      uint32 = 100003
	nfsVersion3     uint32 = 3
	nfsVersion4     uint32 = 4
	nfsProcCompound uint32 = 1
	mountProgram    uint32 = 100005
	mountVersion1   uint32 = 1
	mountVersion3   uint32 = 3
	mountProcExport uint32 = 5
	portmapProgram  uint32 = 100000
	portmapVersion2 uint32 = 2
	portmapProcGet  uint32 = 3
	rpcCall         uint32 = 0
	rpcReply        uint32 = 1
	rpcVersion      uint32 = 2
	authNull        uint32 = 0
	msgAccepted     uint32 = 0
	successState    uint32 = 0
	authSys         uint32 = 1
	ipProtoTCP      uint32 = 6
	nfs4MinorZero   uint32 = 0
	nfs4OpLookup    uint32 = 15
	nfs4OpPutRootFH uint32 = 24
	nfs4OpReadDir   uint32 = 26
)

type nfsExport struct {
	Path   string
	Groups []string
}

type rpcAuthFlavor struct {
	Name string
	Type uint32
	Cred []byte
}

func NFSScan(info *Common.HostInfo) error {
	target := fmt.Sprintf("%s:%s", info.Host, info.Ports)
	Common.LogDebug(fmt.Sprintf("开始扫描 %s", target))

	timeout := time.Duration(Common.Timeout) * time.Second
	exports, mountVersion, mountPort, err := listNFSExports(info.Host, timeout)
	if err == nil && len(exports) > 0 {
		saveNFSResult(info, exports, mountVersion, mountPort)
		return nil
	}

	paths, pseudoErr := listNFSv4PseudoExports(info.Host, timeout)
	if len(paths) > 0 {
		Common.LogSuccess(fmt.Sprintf("NFS服务 %s 通过2049/TCP best-effort 枚举目录: %s",
			target, strings.Join(paths, "; ")))
		saveNFSv4BestEffortResult(info, paths, err)
		return nil
	}

	if detected, version, detectErr := detectNFSService(info.Host, info.Ports, timeout); detectErr == nil && detected {
		msg := fmt.Sprintf("发现NFS服务 %s 版本: v%d", target, version)
		if err != nil {
			msg += fmt.Sprintf(" 共享目录枚举失败: %v", err)
		}
		if pseudoErr != nil {
			msg += fmt.Sprintf(" pseudo-root遍历失败: %v", pseudoErr)
		}
		Common.LogSuccess(msg)
		saveNFSDetection(info, version, err, pseudoErr)
		return nil
	}

	if err != nil {
		return err
	}
	return nil
}

func listNFSExports(host string, timeout time.Duration) ([]nfsExport, uint32, uint32, error) {
	mountPort, mountVersion, err := getMountPort(host, timeout)
	if err != nil {
		return nil, 0, 0, err
	}

	exports, err := callMountExport(host, mountPort, mountVersion, timeout)
	if err != nil {
		return nil, 0, 0, err
	}
	if len(exports) == 0 {
		return nil, mountVersion, mountPort, fmt.Errorf("未枚举到共享目录")
	}
	return exports, mountVersion, mountPort, nil
}

func getMountPort(host string, timeout time.Duration) (uint32, uint32, error) {
	versions := []uint32{mountVersion3, mountVersion1}
	var lastErr error

	for _, version := range versions {
		port, err := getRPCPort(host, mountProgram, version, timeout)
		if err == nil && port != 0 {
			return port, version, nil
		}
		if err != nil {
			lastErr = err
		}
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("mountd未注册TCP端口")
	}
	return 0, 0, lastErr
}

func getRPCPort(host string, program, version uint32, timeout time.Duration) (uint32, error) {
	payload := newRPCMessage(portmapProgram, portmapVersion2, portmapProcGet, func(buf *bytes.Buffer) {
		writeUint32(buf, program)
		writeUint32(buf, version)
		writeUint32(buf, ipProtoTCP)
		writeUint32(buf, 0)
	})

	reply, err := rpcTCPCall(host, 111, timeout, payload)
	if err != nil {
		return 0, err
	}

	parser := newXDRParser(reply)
	if err := parser.skipRPCReplyHeader(); err != nil {
		return 0, err
	}
	port, err := parser.uint32()
	if err != nil {
		return 0, err
	}
	return port, nil
}

func callMountExport(host string, port, version uint32, timeout time.Duration) ([]nfsExport, error) {
	payload := newRPCMessage(mountProgram, version, mountProcExport, nil)
	reply, err := rpcTCPCall(host, port, timeout, payload)
	if err != nil {
		return nil, err
	}

	parser := newXDRParser(reply)
	if err := parser.skipRPCReplyHeader(); err != nil {
		return nil, err
	}

	var exports []nfsExport
	for {
		hasValue, err := parser.bool()
		if err != nil {
			return nil, err
		}
		if !hasValue {
			break
		}

		path, err := parser.string()
		if err != nil {
			return nil, err
		}

		var groups []string
		for {
			hasGroup, err := parser.bool()
			if err != nil {
				return nil, err
			}
			if !hasGroup {
				break
			}

			group, err := parser.string()
			if err != nil {
				return nil, err
			}
			if group != "" {
				groups = append(groups, group)
			}
		}

		exports = append(exports, nfsExport{
			Path:   path,
			Groups: groups,
		})
	}

	return exports, nil
}

func detectNFSService(host, port string, timeout time.Duration) (bool, uint32, error) {
	portNum := uint32(2049)
	if port != "" {
		if parsed, err := parseUint32(port); err == nil {
			portNum = parsed
		}
	}

	for _, version := range []uint32{nfsVersion4, nfsVersion3} {
		payload := newRPCMessage(nfsProgram, version, 0, nil)
		reply, err := rpcTCPCall(host, portNum, timeout, payload)
		if err != nil {
			continue
		}

		parser := newXDRParser(reply)
		if err := parser.skipRPCReplyHeader(); err == nil {
			return true, version, nil
		}
	}

	return false, 0, fmt.Errorf("未识别到NFS RPC响应")
}

func listNFSv4PseudoExports(host string, timeout time.Duration) ([]string, error) {
	const (
		maxDepth       = 3
		maxEntries     = 64
		maxEntriesScan = 32
	)

	seen := make(map[string]struct{})
	var results []string

	var walk func(path []string, depth int) error
	walk = func(path []string, depth int) error {
		if len(results) >= maxEntries || depth > maxDepth {
			return nil
		}

		entries, err := nfs4ReadDir(host, path, timeout)
		if err != nil {
			return err
		}

		scanned := 0
		for _, name := range entries {
			if name == "" || name == "." || name == ".." {
				continue
			}
			scanned++
			if scanned > maxEntriesScan {
				break
			}

			nextPath := append(append([]string{}, path...), name)
			fullPath := "/" + strings.Join(nextPath, "/")
			if _, ok := seen[fullPath]; ok {
				continue
			}
			seen[fullPath] = struct{}{}
			results = append(results, fullPath)

			if len(results) >= maxEntries {
				break
			}
			if depth < maxDepth {
				_ = walk(nextPath, depth+1)
			}
		}
		return nil
	}

	if err := walk(nil, 0); err != nil {
		return nil, err
	}
	if len(results) == 0 {
		return nil, fmt.Errorf("未从pseudo-root发现可见目录")
	}
	return results, nil
}

func nfs4ReadDir(host string, path []string, timeout time.Duration) ([]string, error) {
	var lastErr error
	for _, flavor := range getNFSv4AuthFlavors(host) {
		entries, err := nfs4ReadDirWithFlavor(host, path, timeout, flavor)
		if err == nil {
			return entries, nil
		}
		lastErr = fmt.Errorf("%s: %w", flavor.Name, err)
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("NFSv4 READDIR失败")
	}
	return nil, lastErr
}

func nfs4ReadDirWithFlavor(host string, path []string, timeout time.Duration, flavor rpcAuthFlavor) ([]string, error) {
	payload := newRPCMessageWithCreds(nfsProgram, nfsVersion4, nfsProcCompound, flavor.Type, flavor.Cred, func(buf *bytes.Buffer) {
		writeString(buf, "")
		writeUint32(buf, nfs4MinorZero)

		opCount := 2 + len(path)
		writeUint32(buf, uint32(opCount))

		writeUint32(buf, nfs4OpPutRootFH)
		for _, segment := range path {
			writeUint32(buf, nfs4OpLookup)
			writeString(buf, segment)
		}

		writeUint32(buf, nfs4OpReadDir)
		writeUint64(buf, 0)
		buf.Write(make([]byte, 8))
		writeUint32(buf, 4096)
		writeUint32(buf, 16384)
		writeUint32(buf, 0)
	})

	reply, err := rpcTCPCall(host, 2049, timeout, payload)
	if err != nil {
		return nil, err
	}

	parser := newXDRParser(reply)
	if err := parser.skipRPCReplyHeader(); err != nil {
		return nil, err
	}

	compoundStatus, err := parser.uint32()
	if err != nil {
		return nil, err
	}
	if compoundStatus != 0 {
		return nil, fmt.Errorf("NFSv4 COMPOUND失败: %d", compoundStatus)
	}

	if _, err := parser.string(); err != nil {
		return nil, err
	}

	opCount, err := parser.uint32()
	if err != nil {
		return nil, err
	}

	var entries []string
	for i := uint32(0); i < opCount; i++ {
		op, err := parser.uint32()
		if err != nil {
			return nil, err
		}
		status, err := parser.uint32()
		if err != nil {
			return nil, err
		}
		if status != 0 {
			return nil, fmt.Errorf("NFSv4操作失败 op=%d status=%d", op, status)
		}

		switch op {
		case nfs4OpPutRootFH, nfs4OpLookup:
		case nfs4OpReadDir:
			parsedEntries, err := parseNFSv4ReadDirResult(parser)
			if err != nil {
				return nil, err
			}
			entries = append(entries, parsedEntries...)
		default:
			return nil, fmt.Errorf("未处理的NFSv4操作响应: %d", op)
		}
	}

	return entries, nil
}

func parseNFSv4ReadDirResult(parser *xdrParser) ([]string, error) {
	if _, err := parser.opaque(8); err != nil {
		return nil, err
	}

	var entries []string
	for {
		hasEntry, err := parser.bool()
		if err != nil {
			return nil, err
		}
		if !hasEntry {
			break
		}

		if _, err := parser.uint64(); err != nil {
			return nil, err
		}

		name, err := parser.string()
		if err != nil {
			return nil, err
		}
		entries = append(entries, name)

		if err := parser.skipFattr4(); err != nil {
			return nil, err
		}
	}

	if _, err := parser.bool(); err != nil {
		return nil, err
	}
	return entries, nil
}

func saveNFSResult(info *Common.HostInfo, exports []nfsExport, mountVersion, mountPort uint32) {
	target := fmt.Sprintf("%s:%s", info.Host, info.Ports)
	exportStrings := formatNFSExports(exports)
	Common.LogSuccess(fmt.Sprintf("NFS服务 %s mountd: %d(v%d) 共享目录: %s",
		target, mountPort, mountVersion, strings.Join(exportStrings, "; ")))

	result := &Common.ScanResult{
		Time:   time.Now(),
		Type:   Common.SERVICE,
		Target: info.Host,
		Status: "detected",
		Details: map[string]interface{}{
			"port":          info.Ports,
			"service":       "nfs",
			"mountd_port":   mountPort,
			"mountd_ver":    mountVersion,
			"export_count":  len(exports),
			"exports":       exportStrings,
			"shares":        exportStrings,
			"enumerated_by": "mountd-export",
		},
	}
	Common.SaveResult(result)
}

func saveNFSv4BestEffortResult(info *Common.HostInfo, paths []string, mountErr error) {
	details := map[string]interface{}{
		"port":          info.Ports,
		"service":       "nfs",
		"version":       4,
		"shares":        paths,
		"exports":       paths,
		"export_count":  len(paths),
		"enumerated_by": "nfsv4-pseudo-root-best-effort",
	}
	if mountErr != nil {
		details["mountd_error"] = mountErr.Error()
	}

	result := &Common.ScanResult{
		Time:    time.Now(),
		Type:    Common.SERVICE,
		Target:  info.Host,
		Status:  "detected",
		Details: details,
	}
	Common.SaveResult(result)
}

func saveNFSDetection(info *Common.HostInfo, version uint32, enumErr error, pseudoErr error) {
	details := map[string]interface{}{
		"port":    info.Ports,
		"service": "nfs",
		"version": version,
	}
	if enumErr != nil {
		details["enum_error"] = enumErr.Error()
	}
	if pseudoErr != nil {
		details["pseudo_root_error"] = pseudoErr.Error()
	}

	result := &Common.ScanResult{
		Time:    time.Now(),
		Type:    Common.SERVICE,
		Target:  info.Host,
		Status:  "detected",
		Details: details,
	}
	Common.SaveResult(result)
}

func formatNFSExports(exports []nfsExport) []string {
	result := make([]string, 0, len(exports))
	for _, export := range exports {
		if len(export.Groups) == 0 {
			result = append(result, export.Path)
			continue
		}
		result = append(result, fmt.Sprintf("%s [%s]", export.Path, strings.Join(export.Groups, ",")))
	}
	return result
}

func rpcTCPCall(host string, port uint32, timeout time.Duration, payload []byte) ([]byte, error) {
	address := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	if _, err := conn.Write(payload); err != nil {
		return nil, err
	}

	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}

	recordHeader := binary.BigEndian.Uint32(header)
	length := recordHeader & 0x7fffffff
	if recordHeader>>31 == 0 {
		return nil, fmt.Errorf("收到分片RPC响应，当前未支持")
	}
	if length == 0 {
		return nil, fmt.Errorf("RPC响应为空")
	}

	body := make([]byte, length)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, err
	}
	return body, nil
}

func newRPCMessage(program, version, procedure uint32, writeArgs func(*bytes.Buffer)) []byte {
	return newRPCMessageWithCreds(program, version, procedure, authNull, nil, writeArgs)
}

func newRPCMessageWithCreds(program, version, procedure uint32, flavor uint32, cred []byte, writeArgs func(*bytes.Buffer)) []byte {
	body := &bytes.Buffer{}
	writeUint32(body, uint32(rand.Uint32()))
	writeUint32(body, rpcCall)
	writeUint32(body, rpcVersion)
	writeUint32(body, program)
	writeUint32(body, version)
	writeUint32(body, procedure)
	if len(cred) > 0 {
		writeUint32(body, flavor)
		writeUint32(body, uint32(len(cred)))
		body.Write(cred)
	} else {
		writeUint32(body, flavor)
		writeUint32(body, 0)
	}
	writeUint32(body, authNull)
	writeUint32(body, 0)
	if writeArgs != nil {
		writeArgs(body)
	}

	packet := &bytes.Buffer{}
	writeUint32(packet, uint32(body.Len())|0x80000000)
	packet.Write(body.Bytes())
	return packet.Bytes()
}

func getNFSv4AuthFlavors(host string) []rpcAuthFlavor {
	flavors := []rpcAuthFlavor{
		{Name: "AUTH_NULL", Type: authNull, Cred: nil},
	}

	if realFlavor, ok := getRealAuthSysFlavor(); ok {
		flavors = append(flavors, realFlavor)
	}
	if localRootFlavor, ok := getLocalRootAuthSysFlavor(); ok {
		flavors = append(flavors, localRootFlavor)
	}

	for _, hostname := range getAuthSysHostnames(host) {
		flavors = append(flavors, rpcAuthFlavor{
			Name: fmt.Sprintf("AUTH_SYS[root@%s]", hostname),
			Type: authSys,
			Cred: newAuthSysCredential(hostname, 0, 0, []uint32{0}),
		})
	}

	return flavors
}

func getRealAuthSysFlavor() (rpcAuthFlavor, bool) {
	hostname, err := os.Hostname()
	if err != nil || strings.TrimSpace(hostname) == "" {
		hostname = "localhost"
	}

	groups, err := os.Getgroups()
	if err != nil {
		groups = []int{os.Getgid()}
	}
	groupIDs := make([]uint32, 0, len(groups))
	for _, groupID := range groups {
		if groupID < 0 {
			continue
		}
		groupIDs = append(groupIDs, uint32(groupID))
	}
	if len(groupIDs) == 0 {
		groupIDs = []uint32{uint32(os.Getgid())}
	}

	return rpcAuthFlavor{
		Name: fmt.Sprintf("AUTH_SYS[real:%s uid=%d gid=%d]", hostname, os.Getuid(), os.Getgid()),
		Type: authSys,
		Cred: newAuthSysCredential(hostname, uint32(os.Getuid()), uint32(os.Getgid()), groupIDs),
	}, true
}

func getLocalRootAuthSysFlavor() (rpcAuthFlavor, bool) {
	hostname, err := os.Hostname()
	if err != nil || strings.TrimSpace(hostname) == "" {
		hostname = "localhost"
	}

	return rpcAuthFlavor{
		Name: fmt.Sprintf("AUTH_SYS[local-root:%s]", hostname),
		Type: authSys,
		Cred: newAuthSysCredential(hostname, 0, 0, []uint32{0}),
	}, true
}

func getAuthSysHostnames(host string) []string {
	seen := make(map[string]struct{})
	var hostnames []string

	add := func(value string) {
		value = strings.TrimSpace(strings.TrimSuffix(value, "."))
		if value == "" {
			return
		}
		if _, ok := seen[value]; ok {
			return
		}
		seen[value] = struct{}{}
		hostnames = append(hostnames, value)
	}

	add(host)

	if names, err := net.LookupAddr(host); err == nil {
		for _, name := range names {
			add(name)
		}
	}

	add("localhost")
	return hostnames
}

func newAuthSysCredential(hostname string, uid, gid uint32, gids []uint32) []byte {
	buf := &bytes.Buffer{}
	writeUint32(buf, uint32(time.Now().Unix()))
	writeString(buf, hostname)
	writeUint32(buf, uid)
	writeUint32(buf, gid)
	writeUint32(buf, uint32(len(gids)))
	for _, groupID := range gids {
		writeUint32(buf, groupID)
	}
	return buf.Bytes()
}

func writeUint32(buf *bytes.Buffer, value uint32) {
	_ = binary.Write(buf, binary.BigEndian, value)
}

func writeUint64(buf *bytes.Buffer, value uint64) {
	_ = binary.Write(buf, binary.BigEndian, value)
}

func writeString(buf *bytes.Buffer, value string) {
	writeUint32(buf, uint32(len(value)))
	buf.WriteString(value)
	padding := (4 - (len(value) % 4)) % 4
	if padding > 0 {
		buf.Write(make([]byte, padding))
	}
}

func parseUint32(value string) (uint32, error) {
	var port uint32
	_, err := fmt.Sscanf(value, "%d", &port)
	return port, err
}

type xdrParser struct {
	data []byte
	pos  int
}

func newXDRParser(data []byte) *xdrParser {
	return &xdrParser{data: data}
}

func (p *xdrParser) uint32() (uint32, error) {
	if p.pos+4 > len(p.data) {
		return 0, io.ErrUnexpectedEOF
	}
	value := binary.BigEndian.Uint32(p.data[p.pos : p.pos+4])
	p.pos += 4
	return value, nil
}

func (p *xdrParser) bool() (bool, error) {
	value, err := p.uint32()
	if err != nil {
		return false, err
	}
	return value != 0, nil
}

func (p *xdrParser) uint64() (uint64, error) {
	if p.pos+8 > len(p.data) {
		return 0, io.ErrUnexpectedEOF
	}
	value := binary.BigEndian.Uint64(p.data[p.pos : p.pos+8])
	p.pos += 8
	return value, nil
}

func (p *xdrParser) opaque(length int) ([]byte, error) {
	if p.pos+length > len(p.data) {
		return nil, io.ErrUnexpectedEOF
	}
	value := p.data[p.pos : p.pos+length]
	p.pos += length

	padding := (4 - (length % 4)) % 4
	if p.pos+padding > len(p.data) {
		return nil, io.ErrUnexpectedEOF
	}
	p.pos += padding
	return value, nil
}

func (p *xdrParser) string() (string, error) {
	length, err := p.uint32()
	if err != nil {
		return "", err
	}
	value, err := p.opaque(int(length))
	if err != nil {
		return "", err
	}
	return string(value), nil
}

func (p *xdrParser) skipFattr4() error {
	maskLen, err := p.uint32()
	if err != nil {
		return err
	}
	for i := uint32(0); i < maskLen; i++ {
		if _, err := p.uint32(); err != nil {
			return err
		}
	}

	attrListLen, err := p.uint32()
	if err != nil {
		return err
	}
	_, err = p.opaque(int(attrListLen))
	return err
}

func (p *xdrParser) skipRPCReplyHeader() error {
	if _, err := p.uint32(); err != nil {
		return err
	}

	msgType, err := p.uint32()
	if err != nil {
		return err
	}
	if msgType != rpcReply {
		return fmt.Errorf("无效RPC响应类型: %d", msgType)
	}

	replyState, err := p.uint32()
	if err != nil {
		return err
	}
	if replyState != msgAccepted {
		return fmt.Errorf("RPC响应被拒绝: %d", replyState)
	}

	if _, err := p.uint32(); err != nil {
		return err
	}
	verifierLength, err := p.uint32()
	if err != nil {
		return err
	}
	if _, err := p.opaque(int(verifierLength)); err != nil {
		return err
	}

	acceptState, err := p.uint32()
	if err != nil {
		return err
	}
	if acceptState != successState {
		return fmt.Errorf("RPC调用失败: %d", acceptState)
	}
	return nil
}
