package psapi

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"
)

const (
	PROCESS_VM_READ = 0x0010
	PROCESS_QUERY_INFORMATION = 0x0400
	PROCESS_ALL_ACCESS = 0x000F0000 | 0x00100000 | 0xFFF
)


func errno(e1 error) error {
	if e1, ok := e1.(syscall.Errno); ok && e1 == 0 {
		e1 = syscall.EINVAL
	}
	return e1
}

func EnumProcesses() (pids [2048]uint32, processNumber uint32, err error){
	var (
		psapi = syscall.NewLazyDLL("Psapi.dll")
		procEnumProcesses = psapi.NewProc("EnumProcesses")
	)

	var lpcbNeeded uint32

	r1, _, e1 := procEnumProcesses.Call(
		uintptr(unsafe.Pointer(&pids[0])),
		uintptr(len(pids))*unsafe.Sizeof(pids[0]),
		uintptr(unsafe.Pointer(&lpcbNeeded)),
	)

	if r1==0 {
		err = errno(e1)
	} else{
		processNumber = uint32(uintptr(lpcbNeeded) / unsafe.Sizeof(pids[0]))
	}
	//defer psapi.Release()

	return pids, processNumber, err
}

func OpenProcess(dwDesiredAccess uint32, bInheritHandle int, dwProcessId uint32)(processHandle uintptr, err error){

	//dwDesiredAccess = PROCESS_VM_READ | PROCESS_QUERY_INFORMATION
	//bInheritHandle = 0
	//dwProcessId = 6124

	//Handle for function return:
	var r1 uintptr

	var (
		kernel32 = syscall.NewLazyDLL("kernel32.dll")
		procOpenProcesses = kernel32.NewProc("OpenProcess")
	)

	r1, _, e1 := procOpenProcesses.Call(uintptr(dwDesiredAccess),
		uintptr(bInheritHandle),
		uintptr(dwProcessId),
	)

	if r1==0 {
		err = errno(e1)
	} else{
		processHandle = r1
	}

	return processHandle,err

}

func CloseHandle(handle uintptr)(success bool, err error){

	var (
		kernel32 = syscall.NewLazyDLL("kernel32.dll")
		procCloseHandle = kernel32.NewProc("CloseHandle")
	)

	r1, _, e1 := procCloseHandle.Call(handle)

	if r1==0 {
		err = errno(e1)
		success = false
	} else{
		success = true
	}

	return success,err

}

func EnumProcessModules(processHandle uintptr)(processModules [2048]uintptr, moduleNumber int, err error){

	var (
		psapi = syscall.NewLazyDLL("Psapi.dll")
		procEnumProcessModules = psapi.NewProc("EnumProcessModules")
	)

	//HMODULE is same type as handle, this time we need an array :
	var lphModule [2048]uintptr
	var lpcbNeeded uint32
	var cb = unsafe.Sizeof(lphModule[0])
	cb = cb*uintptr(len(lphModule))


	r1, _, e1 := procEnumProcessModules.Call(
		processHandle,
		uintptr(unsafe.Pointer(&lphModule[0])),
		cb,
		uintptr(unsafe.Pointer(&lpcbNeeded)),
	)

	if r1==0 {
		err = errno(e1)
	}else{
		moduleNumber = int(uintptr(lpcbNeeded) / unsafe.Sizeof(lphModule[0]))
		processModules = lphModule
	}

	return processModules, moduleNumber ,err

}

func GetModuleBaseNameA(processHandle uintptr, processModule uintptr)(moduleName string, err error){
	var (
		psapi = syscall.NewLazyDLL("Psapi.dll")
		procGetModuleBaseNameA = psapi.NewProc("GetModuleBaseNameA")
	)
	var lpBaseName [255]byte
	var nSize uint32 = 255

	r1, _, e1 := procGetModuleBaseNameA.Call(
		processHandle,
		processModule,
		uintptr(unsafe.Pointer(&lpBaseName)),
		uintptr(nSize),
	)

	if r1==0 {
		err = errno(e1)
	}else{
		moduleName = string(lpBaseName[:])
		moduleName = strings.ReplaceAll(moduleName, string(0x00), "")
	}
	return moduleName, err
}

func GetModuleFileNameExA(processHandle uintptr, moduleHandle uintptr)(processFullPath string, err error){
	var (
		psapi = syscall.NewLazyDLL("Psapi.dll")
		GetModuleFileNameExA = psapi.NewProc("GetModuleFileNameExA")
	)
	var lpFilename [255]byte
	var nSize uint32 = 255

	r1, _, e1 := GetModuleFileNameExA.Call(
		processHandle,
		moduleHandle,
		uintptr(unsafe.Pointer(&lpFilename)),
		uintptr(nSize),
	)

	if r1==0 {
		err = errno(e1)
	}else{
		processFullPath = string(lpFilename[:])
		processFullPath = strings.ReplaceAll(processFullPath, string(0x00), "")
	}
	return processFullPath, err
}

func EnumAllProcessAndModules_test(){

	/*
	Functions used to enumerate PID, process names & associated modules:

	EnumProcess() --> Get PID list
	OpenProcess() --> Retrieves a Handle in order to interact with a process
	EnumProcessModules() --> Retrieves Module list of a process
	GetModuleBaseName() --> Retrieves the base name of the specified module.
	CloseHandle() --> Close a process Handle
	*/

	// Following target a specific process PID [3848]
	fmt.Println("=============== ! EnumProcesses TEST ! ===============")
	pidList, numberOfprocess, _ := EnumProcesses()
	fmt.Println("There is ", numberOfprocess, " proceses runnng")
	fmt.Println("Complete PID list : ", pidList[0:numberOfprocess])
	fmt.Println("======================================================")

	fmt.Println("================ ! OpenProcess TEST ! ================")
	processHandle, errOpenprocess := OpenProcess(0x0400,0,3848)
	fmt.Println(errOpenprocess)
	fmt.Println("Printing the Handle (no-sense) : ", processHandle)
	fmt.Println("======================================================")

	/*
		// Test of closing handle function:
		success, err := CloseHandle(handle)
		fmt.Println("Success : ", success)
		fmt.Println("Error : ", err)
	*/

	fmt.Println("============= ! EnumProcessModules TEST ! =============")
	processModules, _, errEnumProcessModules := EnumProcessModules(processHandle)
	fmt.Println(errEnumProcessModules)
	fmt.Println("======================================================")


	fmt.Println("============= ! GetModuleBaseNameA TEST ! =============")
	moduleName, _ := GetModuleBaseNameA(processHandle,processModules[0])
	fmt.Println(moduleName)

	fmt.Println("============= ! PSAPI complete TEST ! =============")
	pidList, numberOfprocess, _ = EnumProcesses()
	fmt.Println(pidList)

	// Following target all system processes (with error handling):
	for _, aProcess := range pidList[:numberOfprocess] {
		processHandle, errOpenprocess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,0,aProcess)

		if errOpenprocess == nil{
			processModules, moduleNumber, errEnumProcessModules := EnumProcessModules(processHandle)

			if errEnumProcessModules == nil{
				moduleName, errGetModuleBaseNameA := GetModuleBaseNameA(processHandle,processModules[0])

				ProcessfullPath, errGetModuleFileNameExA := GetModuleFileNameExA(processHandle,uintptr(unsafe.Pointer(nil)))

				if errGetModuleBaseNameA == nil{

					if errGetModuleFileNameExA == nil{
						fmt.Println("==========================================================================")

						fmt.Println("PID",aProcess," : " ,moduleName)
						fmt.Println("FULL PATH: ", ProcessfullPath)
						fmt.Println("This process also uses the following", moduleNumber, "others modules : [TRUNCATED]")

						//enumarating all process modules:
						/*
						var moduleArray []string
						for _, aModule := range processModules[:moduleNumber] {
							moduleName, errGetModuleBaseNameA = GetModuleBaseNameA(processHandle,aModule)
							moduleArray = append(moduleArray, moduleName)
						}
						fmt.Println(moduleArray)

						 */

						fmt.Println("==========================================================================")
					}else{
						fmt.Println("GetModuleFileNameExA() error:", aProcess, " ", errGetModuleFileNameExA)
					}

				}else{
					fmt.Println("GetModuleBaseNameA() error:", aProcess, " ", errGetModuleBaseNameA)
				}
			}else{
				fmt.Println("EnumProcessModules() error:", aProcess, " ", errEnumProcessModules)
			}
		}else{
			fmt.Println(aProcess, "OpenProcess() error:" , " ", errOpenprocess)
		}
	}
}
