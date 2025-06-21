//go:build windows

package main

import (
	"os"
	"syscall"
	"unsafe"
)

var (
	modkernel32 = syscall.NewLazyDLL("kernel32.dll")
	modadvapi32 = syscall.NewLazyDLL("advapi32.dll")
	
	procGetCurrentProcess = modkernel32.NewProc("GetCurrentProcess")
	procOpenProcessToken  = modadvapi32.NewProc("OpenProcessToken")
	procGetTokenInformation = modadvapi32.NewProc("GetTokenInformation")
)

const (
	tokenQuery           = 0x0008
	tokenElevationType   = 20
)

// TOKEN_ELEVATION structure
type tokenElevation struct {
	TokenIsElevated uint32
}

// checkPrivileges checks if the program is running with administrator privileges on Windows
func checkPrivileges() bool {
	// Try a simple check first - attempt to open a privileged resource
	_, err := os.Open("\\\\.\\PHYSICALDRIVE0")
	if err == nil {
		return true
	}
	
	// More thorough check using Windows API
	var token syscall.Token
	
	process, _, _ := procGetCurrentProcess.Call()
	if process == 0 {
		return false
	}
	
	ret, _, _ := procOpenProcessToken.Call(
		process,
		tokenQuery,
		uintptr(unsafe.Pointer(&token)),
	)
	if ret == 0 {
		return false
	}
	defer token.Close()
	
	var elevation tokenElevation
	var size uint32
	ret, _, _ = procGetTokenInformation.Call(
		uintptr(token),
		tokenElevationType,
		uintptr(unsafe.Pointer(&elevation)),
		unsafe.Sizeof(elevation),
		uintptr(unsafe.Pointer(&size)),
	)
	
	if ret == 0 {
		return false
	}
	
	return elevation.TokenIsElevated != 0
}