// +build windows,amd64

package main

// todo 32/34 support


import (
	"encoding/binary"
	"fmt"
	"syscall"
	"unsafe"
)

type IMAGE_SECTION_HEADER struct {
	Name [IMAGE_SIZEOF_SHORT_NAME]byte
	Misc_PhysicalAddressOrVirtualSize	 uint32
	VirtualAddress       uint32
	SizeOfRawData        uint32
	PointerToRawData     uint32
	PointerToRelocations uint32
	PointerToLinenumbers uint32
	NumberOfRelocations  uint16
	NumberOfLinenumbers  uint16
	Characteristics      uint32
	// contains filtered or unexported fields
}

type SERVICE_STATUS_PROCESS struct {
	dwServiceType             uint32
	dwCurrentState            uint32
	dwControlsAccepted        uint32
	dwWin32ExitCode           uint32
	dwServiceSpecificExitCode uint32
	dwCheckPoint              uint32
	dwWaitHint                uint32
	dwProcessId               uint32
	dwServiceFlags            uint32
}

type IMAGE_FILE_HEADER struct { //physical format of a file
	Machine uint16
	NumberOfSections uint16
	TimeDateStamp uint32
	PointerToSymbolTable uint32
	NumberOfSymbols uint32
	SizeOfOptionalHeader uint16
	Characteristics uint16
}

type IMAGE_DOS_HEADER struct {  // DOS .EXE header only used for backwards compatibility
	e_magic uint16                    // Magic number
	e_cblp uint16                     // Bytes on last page of file
	e_cp uint16                       // Pages in file
	e_crlc uint16                     // Relocations
	e_cparhdr uint16                  // Size of header in paragraphs
	e_minalloc uint16                 // Minimum extra paragraphs needed
	e_maxalloc uint16                 // Maximum extra paragraphs needed
	e_ss uint16                       // Initial (relative) SS value
	e_sp uint16                       // Initial SP value
	e_csum uint16                     // Checksum
	e_ip uint16                       // Initial IP value
	e_cs uint16                       // Initial (relative) CS value
	e_lfarlc uint16                   // File address of relocation table
	e_ovno uint16                     // Overlay number
	e_res[4] uint16                   // Reserved s
	e_oemid uint16                    // OEM identifier (for e_oeminfo)
	e_oeminfo uint16                  // OEM information e_oemid specific
	e_res2[10] uint16                 // Reserved s
	e_lfanew  int32              // File address of new exe header

}

type IMAGE_OPTIONAL_HEADER64 struct {
	Magic                       uint16
	MajorLinkerVersion          byte
	MinorLinkerVersion          byte
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	ImageBase                   uint64
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint64
	SizeOfStackCommit           uint64
	SizeOfHeapReserve           uint64
	SizeOfHeapCommit            uint64
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32
	DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES]				IMAGE_DATA_DIRECTORY
}
/*
type IMAGE_OPTIONAL_HEADER32 struct {
	Magic                       uint16
	MajorLinkerVersion          byte
	MinorLinkerVersion          byte
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	ImageBase                   uint32 // main difference between 32 and 64
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint32
	SizeOfStackCommit           uint32
	SizeOfHeapReserve           uint32
	SizeOfHeapCommit            uint32
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32
	DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES]				IMAGE_DATA_DIRECTORY
}*/

type IMAGE_DATA_DIRECTORY struct{
	VirtualAddress uint32
	Size 			uint32
}
type SIZE_T uint64 // uint32 for 32bits procs

type IMAGE_NT_HEADERS64 struct {
	Signature      uint32
	FileHeader     IMAGE_FILE_HEADER
	OptionalHeader IMAGE_OPTIONAL_HEADER64
}
/*
type IMAGE_NT_HEADERS32 struct {
	Signature      uint32
	FileHeader     IMAGE_FILE_HEADER
	OptionalHeader IMAGE_OPTIONAL_HEADER32
}
*/

type BASE_RELOCATION_BLOCK struct {
	PageAddress      uint32
	BlockSize     uint32
}

type BASE_RELOCATION_ENTRY struct {
	Offset      uint16
	Type     uint16
}

type IMAGE_IMPORT_DESCRIPTOR struct{
	Characteristics uint32
	OriginalFirstThunk uint32
	TimeDateStamp uint32
	ForwarderChain uint32
	Name uint32
	FirstThunk uint32
}

func NewBaseReolocationEntry()(BaseReolocationEntry BASE_RELOCATION_ENTRY){
	BaseReolocationEntry.Offset = 12
	BaseReolocationEntry.Type = 4
	return BaseReolocationEntry
}
const(
	GENERIC_READ = 0x80000000
	GENERIC_WRITE = 0x40000000
	OPEN_EXISTING = 3
	HEAP_ZERO_MEMORY = 0x00000008
	IMAGE_SIZEOF_SHORT_NAME = 8
	IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16
	IMAGE_DIRECTORY_ENTRY_BASERELOC = 5
)

func StringToCharPtr(str string) *uint8 {
	chars := append([]byte(str), 0) // null terminated
	return &chars[0]
}

func errno(e1 error) error {
	if e1, ok := e1.(syscall.Errno); ok && e1 == 0 {
		e1 = syscall.EINVAL
	}
	return e1
}

func CreateFileA(dllPath string)(fileHandle uintptr, err error){
	// https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea

	var (
		kernel32 = syscall.NewLazyDLL("kernel32.dll")
		CreateFileA = kernel32.NewProc("CreateFileA")
	)

	//First param is LPCSTR so we use StringToCharPtr()

	r1, _, e1 := CreateFileA.Call(
		uintptr(unsafe.Pointer(StringToCharPtr(dllPath))),
		GENERIC_READ,
		0,
		0,
		OPEN_EXISTING,
		0,
		0,
	)

	if r1==0 {
		err = errno(e1)
	}

	return r1, err
}

func GetFileSizeEx(fileHandle uintptr)(fileSize uint64, err error){
	// https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfilesize

	var (
		kernel32 = syscall.NewLazyDLL("kernel32.dll")
		GetFileSizeEx = kernel32.NewProc("GetFileSizeEx")
	)

	var lpFileSize uint64

	r1, _, e1 := GetFileSizeEx.Call(
		fileHandle,
		uintptr(unsafe.Pointer(&lpFileSize)),
	)

	if r1==0 {
		err = errno(e1)
	}

	return lpFileSize, err
}


func GetProcessHeap()(heapHandle uintptr, err error){
	var (
		kernel32 =
			syscall.NewLazyDLL("kernel32.dll")
		GetProcessHeap = kernel32.NewProc("GetProcessHeap")
	)

	r1, _, e1 := GetProcessHeap.Call()

	if r1==0 {
		err = errno(e1)
	}

	return  r1, err
}

func HeapAlloc(heapHandle uintptr, dllSize uint64)(allocatedMemoryBlock uintptr, err error){
	// https://docs.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapalloc

	var (
		kernel32 = syscall.NewLazyDLL("kernel32.dll")
		HeapAlloc = kernel32.NewProc("HeapAlloc")
	)

	r1, _, e1 := HeapAlloc.Call(
		heapHandle,
		HEAP_ZERO_MEMORY,
		uintptr(dllSize),
	)

	if r1==0 {
		err = errno(e1)
	}

	return  r1, err
}

func ReadFileToMemory(fileHandle uintptr, allocatedMemoryBlock uintptr, dllSize uint64)(err error){

	// copy dll to memory ?

	var (
		kernel32 = syscall.NewLazyDLL("kernel32.dll")
		ReadFile = kernel32.NewProc("ReadFile")
	)

	//var buffer [2048]byte
	//var lpcbNeeded uint32

	r1, _, e1 := ReadFile.Call(
		fileHandle,
		allocatedMemoryBlock,
		uintptr(dllSize),
		0,
		0,
	)

	if r1==0 {
		err = errno(e1)
	}

	return err
}

func VirtualAlloc(startingAddr uintptr, allocationSize uintptr)(baseAddress uintptr, err error){

	var (
		kernel32 = syscall.NewLazyDLL("kernel32.dll")
		VirtualAlloc = kernel32.NewProc("VirtualAlloc")
	)

	r1, _, e1 := VirtualAlloc.Call(
		startingAddr,
		allocationSize,
		MEM_RESERVE | MEM_COMMIT,
		PAGE_EXECUTE_READWRITE,
	)

	if r1==0 {
		err = errno(e1)
	}

	return r1,err
}

func Memcopy(destination uintptr, source uintptr, length uint32)(offsetAddr uintptr, err error){

	var (
		msvcrt = syscall.NewLazyDLL("msvcrt.dll")
		Memcopy = msvcrt.NewProc("memcpy")
	)

	r1, _, e1 := Memcopy.Call(
		destination,
		source,
		uintptr(length),
	)

	if r1==0 {
		err = errno(e1)
	}

	return r1,err
}

func ParseSectionsHeaders(ntHeader *IMAGE_NT_HEADERS64)(allSectionsHeaders[] *IMAGE_SECTION_HEADER){

	// Parsing the first header :
	// https://stackoverflow.com/questions/23498583/pe-section-data
	// https://codemachine.com/downloads/win80/winnt.h
	// https://stackoverflow.com/questions/51844868/empty-data-after-optionalheader
	// IMAGE_FIRST_SECTION doesn't need 32/64 versions since the file header is the same either way.
	var firstSectionHeader = (*IMAGE_SECTION_HEADER)(unsafe.Pointer(uintptr(unsafe.Pointer(ntHeader))  + unsafe.Offsetof(ntHeader.OptionalHeader) + uintptr(ntHeader.FileHeader.SizeOfOptionalHeader)))
	allSectionsHeaders = append(allSectionsHeaders, firstSectionHeader)

	// Parsing next section headers :
	// https://stackoverflow.com/questions/8193862/the-size-of-a-pe-header
	// https://stackoverflow.com/questions/2113751/sizeof-struct-in-go
	// difference between binary.Size(sectionHeader) and unsafe.sizeof...
	// loop on (ntHeader.FileHeader.NumberOfSections - 1) since we already have the first header
	for i := 0; i < int(ntHeader.FileHeader.NumberOfSections-1); i++ {
		var nextSectionHeader = (*IMAGE_SECTION_HEADER)(unsafe.Pointer(uintptr(unsafe.Pointer(firstSectionHeader))  + uintptr(binary.Size(firstSectionHeader))))
		allSectionsHeaders = append(allSectionsHeaders, nextSectionHeader)
		firstSectionHeader = nextSectionHeader
	}

	return allSectionsHeaders
}
func main() {
	/*
		psapi.EnumAllProcessAndModules_test()
		injections.ShellCodeInjection_test(2224)
		fmt.Println(infos.GetNativeSystemInfo())
	*/
	//getSystem.Get_system_test()

	// Load DLL into memory
	fileHandle, err := CreateFileA("Z:\\reflective_dll.x64.dll")
	fmt.Println(fileHandle, err)

	fileSize, err := GetFileSizeEx(fileHandle)
	fmt.Println(fileSize,err)

	heapHandle, err := GetProcessHeap()
	fmt.Println(heapHandle,err)

	allocatedMemoryBlockAddr, err := HeapAlloc(heapHandle, fileSize)
	fmt.Println(allocatedMemoryBlockAddr,err)

	err = ReadFileToMemory(fileHandle,allocatedMemoryBlockAddr,fileSize)
	fmt.Println(err)


	/*
		DLL headers parsing
	*/
	fmt.Println("Trying to to parse IMAGE_DOS_HEADER... ")
	// dosHeaders.e_magic magic byte of MS-DOS file. Byte are : 4D 5A --> MZ
	var dosHeaders = (*IMAGE_DOS_HEADER)(unsafe.Pointer(allocatedMemoryBlockAddr))
	fmt.Println(fmt.Sprintf("%x", dosHeaders.e_magic))


	fmt.Println("================================")
	fmt.Println("Trying to to parse IMAGE_NT_HEADERS64... ")
	// ntHeaders.Signature : A 4-byte signature identifying the file as a PE image. The bytes are "PE\0\0" -->4550 in hex.
	var ntHeaders = (*IMAGE_NT_HEADERS64)(unsafe.Pointer(allocatedMemoryBlockAddr + uintptr(dosHeaders.e_lfanew)))
	fmt.Println(fmt.Sprintf("%x", ntHeaders.Signature))

	fmt.Println("================================")


	fmt.Println("Parsing image size from ntHeaders.OptionalHeader... ")
	var dllImageSize =  ntHeaders.OptionalHeader.SizeOfImage
	fmt.Println(dllImageSize, ntHeaders.OptionalHeader.SectionAlignment)

	fmt.Println("Allocating memory starting from ntHeaders.OptionalHeader.ImageBase... ")
	dllBaseAddr, err := VirtualAlloc(uintptr(ntHeaders.OptionalHeader.ImageBase),uintptr(dllImageSize))
	fmt.Println(dllBaseAddr,err)

	// in case there is a difference between the two addresses
	// If the reserved memory differs from the address given in ImageBase, base relocation as described below must be done.
	var deltaImageBase = dllBaseAddr - uintptr(ntHeaders.OptionalHeader.ImageBase)
	fmt.Println(deltaImageBase)

	fmt.Println("Copying DLL image headers to the newly allocated space...")
	offsetAddr, err := Memcopy(dllBaseAddr, allocatedMemoryBlockAddr, ntHeaders.OptionalHeader.SizeOfHeaders)
	fmt.Println(offsetAddr,err)

	fmt.Println("Copying DLL image sections to the newly allocated space...")
	for _, sectionHeader := range  ParseSectionsHeaders(ntHeaders){
		sectionDestination :=  dllBaseAddr + uintptr(sectionHeader.VirtualAddress)
		sectionBytes := allocatedMemoryBlockAddr + uintptr(sectionHeader.PointerToRawData)

		fmt.Println("Trying to copy: ",string(sectionHeader.Name[:]), "from", sectionBytes, "to", sectionDestination)

		offsetAddr, err := Memcopy(sectionDestination, sectionBytes, sectionHeader.SizeOfRawData)
		fmt.Println(offsetAddr,err)
	}

	fmt.Println(ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
	ImportDescriptor := (*IMAGE_IMPORT_DESCRIPTOR)(unsafe.Pointer(dllBaseAddr + uintptr(ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress)))
	fmt.Println(ImportDescriptor.Name)
	fmt.Println(fmt.Sprintf("%x", ImportDescriptor.Name))
	/*
	var relocations = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
	var relocationTable uintptr = uintptr(relocations.VirtualAddress) + dllBaseAddr
	var relocationsProcessed uint32 = 0

	for relocationsProcessed < relocations.Size {
		var aRelocationBlock BASE_RELOCATION_BLOCK
		var aRelocationEntry BASE_RELOCATION_ENTRY
		var relocationBlock = (*BASE_RELOCATION_BLOCK)(unsafe.Pointer(relocationTable + uintptr(relocationsProcessed)))
		relocationsProcessed += uint32(binary.Size(aRelocationBlock))
		fmt.Println("relocationBlock and relocationsProcessed",relocationBlock,relocationsProcessed)
		var relocationsCount = ((relocationBlock.BlockSize)- uint32(binary.Size(aRelocationBlock))) / uint32(binary.Size(aRelocationEntry))
		fmt.Println("relocationsCount:", relocationsCount)
		var relocationEntries = (*BASE_RELOCATION_ENTRY)(unsafe.Pointer(relocationTable + uintptr(relocationsProcessed)))
		fmt.Println("relocationEntries.Type and relocationEntries.Offset",relocationEntries.Type, relocationEntries.Offset)

		for i := 0;i<int(relocationsCount);i++{
			relocationsProcessed += uint32(binary.Size(aRelocationEntry))

			if relocationEntries.Type == 0
		}
	}
	*/

}

//DLL Technique
// Générer une DLL en golang (voir notes)
// DLL: CallNamedPipeA