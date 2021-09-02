package infos

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"
)

func GetNativeSystemInfo()(ProcessorArchitecture string){

	/*
		https://docs.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getnativesysteminfo
	*/

	var (
		kernel32 = syscall.NewLazyDLL("kernel32.dll")
		GetNativeSystemInfo = kernel32.NewProc("GetNativeSystemInfo")
	)

	type SYSTEM_INFO struct {
		ProcessorArchitecture     uint16
		Reserved                  uint16
		PageSize                  uint32
		MinimumApplicationAddress unsafe.Pointer
		MaximumApplicationAddress unsafe.Pointer
		ActiveProcessorMask       *uint32
		NumberOfProcessors        uint32
		ProcessorType             uint32
		AllocationGranularity     uint32
		ProcessorLevel            uint16
		ProcessorRevision         uint16
	}
	var info SYSTEM_INFO

	_, _, _ = GetNativeSystemInfo.Call(uintptr(unsafe.Pointer(&info)))

	fmt.Print("Processor architecture:  ")
	switch info.ProcessorArchitecture {
	case 9:
		ProcessorArchitecture = "x64"
	case 5:
		ProcessorArchitecture = "ARM"
	case 12:
		ProcessorArchitecture = "ARM64"
	case 6:
		ProcessorArchitecture = "Intel Itanium-based"
	case 0:
		ProcessorArchitecture = "x86"
	case 0xff:
		ProcessorArchitecture ="Unknown architecture"
	}

	return ProcessorArchitecture
}

func GetCurrentUser()(currentUser string){

	var (
		advapi32 = syscall.NewLazyDLL("Advapi32.dll")
		GetUserNameA = advapi32.NewProc("GetUserNameA")
	)

	var buff [2048]byte
	var buffsize uint32 = 2048

	_, _, _ = GetUserNameA.Call(
		uintptr(unsafe.Pointer(&buff)),
		uintptr(unsafe.Pointer(&buffsize)),
	)

	var currentUsername string = string(buff[:])

	return strings.ReplaceAll(currentUsername, string(0x00), "")
}