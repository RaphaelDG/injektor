package main

const(
	MEM_RESERVE = 0x00002000
	MEM_COMMIT = 0x00001000
	PAGE_EXECUTE_READWRITE =  0x40
	//DWORD =
)

type (
	DWORD uint32
    LPVOID uintptr
	HANDLE = uintptr
)


