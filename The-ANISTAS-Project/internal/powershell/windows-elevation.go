//go:build windows
// +build windows

package powershell

import (
	"os"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
)

// GetAdminSysProcAttr returns SysProcAttr configured for admin elevation on Windows
func GetAdminSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		// requesting UAC elevation when on Windows
		// MUST be run as ADMIN
		HideWindow:    true,
		CmdLine:       "",
		CreationFlags: windows.CREATE_NEW_CONSOLE,
		Token:         0,
		ProcessAttributes: &syscall.SecurityAttributes{
			Length:             0,
			SecurityDescriptor: 0,
			InheritHandle:      0,
		},
		ThreadAttributes: &syscall.SecurityAttributes{
			Length:             0,
			SecurityDescriptor: 0,
			InheritHandle:      0,
		},
		NoInheritHandles:           false,
		AdditionalInheritedHandles: nil,
		ParentProcess:              0,
	}
}

// This function checks to see if the current user is an administrator
func amAdmin() bool {
	f, err := os.Open("\\\\.\\PHYSICALDRIVE0")
	if err != nil {
		return false
	}
	_ = f.Close()
	return true
}

// If the user is not an administrator, relaunch the program
func relaunchAsAdmin() error {
	verb := "runas" // tell shell execute to run as admin

	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	args := strings.Join(os.Args[1:], "")

	verbPtr, _ := syscall.UTF16PtrFromString(verb)
	exePtr, _ := syscall.UTF16PtrFromString(exe)
	cwdPtr, _ := syscall.UTF16PtrFromString(cwd)
	argsPtr, _ := syscall.UTF16PtrFromString(args)

	const SW_NORMAL int32 = 1

	// this will prompt the window to allow admin access
	return windows.ShellExecute(0, verbPtr, exePtr, argsPtr, cwdPtr, SW_NORMAL)
}
