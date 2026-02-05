// Diagnostic Service - Microservice 1
// Which is for the collection of sys info using Go sys calls and PS
// ADMIN PRIV REQUIRED

package main

// importing packages:
// "log" logging messages to console
// "net/http" for creating web servers/handling HTTP requests
import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os/exec"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/UUCompSci/The-ANISTAS-Project/internal/powershell"
	pb "github.com/UUCompSci/The-ANISTAS-Project/internal/proto"
)

type diagnosticServer struct {
	pb.UnimplementedDiagnosticServiceServer
}

// RunFTDiagnostics RunFTDDiagnostics exec PS cmd to gather FTP service state
func (s *diagnosticServer) RunFTDiagnostics(ctx context.Context, req *pb.DiagnosticsRequest) (*pb.DiagnosticsResponse, error) {
	log.Printf("Received diagnostic request for host: %s",
		req.TargetHost)

	psScript := `
# Requires -RunAsAdministrator
$results = @{
    ServiceName     = "FTPSVC"
    IsRunning       = $false
    TLSVersion      = ""
    Port            = 21
    AnonymousAccess = $false
    AllowedIPs      = @()
    FIPSCompliant   = "unknown"
}

try {
    # Check if FTP service is running/exists
    $svc = Get-Service -Name "FTPSVC" -ErrorAction SilentlyContinue
    if ($svc) {
        $results.IsRunning = ($svc.Status -eq "Running")

        # Get FTP site configuration from IIS
        Import-Module WebAdministration -ErrorAction SilentlyContinue

        # Check for FTP over TLS configuration
        $ftpSite = Get-Item "IIS:\Sites\*" | Where-Object { $_.bindings.protocol -eq "ftps" } | Select-Object -First 1
        if ($ftpSite) {

            # Check SSL settings
            $sslPolicy = Get-ItemProperty "IIS:\Sites\$($ftpSite.Name)\ftpServer\security\ssl" -Name "sslPolicy" -ErrorAction SilentlyContinue
            if ($sslPolicy) {
                $results.IsFTPS = $true

                # Detect TLS version
                $tls = [System.Net.ServicePointManager]::SecurityProtocol
                $results.TLSVersion = $tls.ToString()
            }

            # Check authentication settings
            $auth = Get-ItemProperty "IIS:\Sites\$($ftpSite.Name)\ftpServer\security\authentication" -ErrorAction SilentlyContinue
            if ($auth) {
                $results.AnonymousAccess = ($auth.AnonymousAuthentication.enabled -eq $True)
            }

            # Check FIPS compliance via registry
            $fipsReg = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy" -Name "Enabled" -ErrorAction SilentlyContinue
            if ($fipsReg.Enabled -eq 1) {
                $results.FIPSCompliant = "true"
            } else {
                $results.FIPSCompliant = "false"
            }
        }
    }
} catch {
    $results.Error = $_.Exception.Message
}

# Output results as JSON
$results | ConvertTo-Json -Compress
`

	// Execute PS w/Admin context
	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", psScript)
	cmd.SysProcAttr = powershell.GetAdminSysProcAttr() // admin elevation

	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("PowerShell execution failed: %v, output: %s", err, string(output))
		return nil, fmt.Errorf("failed to diagnose: %w", err)
	}

	// Parse JSON output
	var psResults struct {
		ServiceName     string   `json:"ServiceName"`
		IsRunning       bool     `json:"IsRunning"`
		IsFTPS          bool     `json:"IsFTPS"`
		TLSVersion      string   `json:"TLSVersion"`
		Port            int      `json:"Port"`
		AnonymousAccess bool     `json:"AnonymousAccess"`
		AllowedIPs      []string `json:"AllowedIPs"`
		FIPSCompliant   string   `json:"FIPSCompliant"`
		Error           string   `json:"Error"`
	}

	if err := json.Unmarshal(output, &psResults); err != nil {
		// If parse fails, return raw output for debug.
		return &pb.DiagnosticsResponse{
			Success:      false,
			ErrorMessage: fmt.Sprintf("parse error: %v, raw: %s", err, string(output)),
		}, nil
	}

	if psResults.Error != "" {
		return &pb.DiagnosticsResponse{
			Success:       false,
			ErrorMessage:  psResults.Error,
			TimestampUnix: time.Now().Unix(),
		}, nil
	}

	return &pb.DiagnosticsResponse{
		Success: true,
		FtpConfig: &pb.FTPConfig{
			ServiceName:     psResults.ServiceName,
			IsRunning:       psResults.IsRunning,
			IsFtps:          psResults.IsFTPS,
			TlsVersion:      psResults.TLSVersion,
			Port:            int32(psResults.Port),
			AnonymousAccess: psResults.AnonymousAccess,
			AllowedIps:      psResults.AllowedIPs,
			FipsCompliant:   psResults.FIPSCompliant,
		},
		RawPowershellOutput: []string{string(output)},
		TimestampUnix:       time.Now().Unix(),
	}, nil
}

func main() {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	s := grpc.NewServer(grpc.Creds(insecure.NewCredentials()))
	pb.RegisterDiagnosticServiceServer(s, &diagnosticServer{})

	log.Printf("server listening at %v", lis.Addr())
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
