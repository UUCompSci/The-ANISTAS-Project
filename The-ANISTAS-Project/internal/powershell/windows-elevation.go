//go:build windows
// +build windows

package powershell

import (
	"syscall"
)

// GetAdminSysProcAttr returns SysProcAttr configured for admin elevation on Windows
func GetAdminSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		// requesting UAC elevation when on Windows
		// MUST be run as ADMIN

		HideWindow:    true,
		CmdLine:       "",
		CreationFlags: syscall.CREATE_NEW_CONSOLE,
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
