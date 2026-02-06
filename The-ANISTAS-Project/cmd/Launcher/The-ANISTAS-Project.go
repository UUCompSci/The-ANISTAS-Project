//go:build windows
// +build windows

package main

import (
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/UUCompSci/The-ANISTAS-Project/internal/powershell"
)

func main() {
	log.Println("=== The ANISTAS Project Launcher ===")

	// 1) Launch as admin
	if !powershell.AmAdmin() {
		log.Println("Not running as admin. Attempting to elevate...")
		if err := powershell.RelaunchAsAdmin(); err != nil {
			log.Fatalf("Failed to relaunch as admin: %v", err)
		}
		return
	}
	log.Println("Running as admin.")

	// 2) Locating sibling .exe files
	exePath, err := os.Executable()
	if err != nil {
		log.Fatalf("Failed to get executable path: %v", err)
	}
	exeDir := filepath.Dir(exePath)
	diagnosticsExe := filepath.Join(exeDir, "diagnostics.exe")
	complianceExe := filepath.Join(exeDir, "compliance.exe")
	pdfExe := filepath.Join(exeDir, "pdf.exe")
	anistasExe := filepath.Join(exeDir, "anistas.exe")

	// 3) starting services
	for _, exe := range []string{diagnosticsExe, complianceExe, pdfExe} {
		cmd := exec.Command(exe)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			log.Fatalf("Failed to start %s: %v", exe, err)
		}
		log.Printf("Started %s (PID %d", exe, cmd.Process.Pid)
		time.Sleep(1 * time.Second)
	}
	orchCmd := exec.Command(anistasExe)
	orchCmd.Stdout = os.Stdout
	orchCmd.Stderr = os.Stderr
	if err := orchCmd.Start(); err != nil {
		log.Fatalf("Failed to start orchestrator: %v", err)
	}
	log.Printf("Started orchestrator (PID %d", orchCmd.Process.Pid)
}
