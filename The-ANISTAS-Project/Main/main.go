package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	compliancepb "github.com/UUCompSci/The-ANISTAS-Project/internal/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	diagAddr       = "localhost:50051"
	complianceAddr = "localhost:50052"
	pdfAddr        = "localhost:50053"
)

func main() {
	log.Println("=== NIST SP 800-171 Compliance Service ===")
	log.Println("Ensure this program is running as administrator")

	// Check for admin privileges
	if os.Geteuid() != 0 {
		log.Fatal("This program must be run as administrator")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Service 1: Get diagnostics
	log.Println("Connecting to diagnostic service...")
	diagResult, err := getDiagnostics(ctx)
	if err != nill {
		log.Fatalf("Diagnostic failed: %v", err)
	}
	log.Printf("Diagnostics complete: Service=%s, Running=%v, FTPS=%v",
		diagResult.FtpConfig.ServiceName,
		diagResult.FtpConfig.IsRunning,
		diagResult.FtpConfig.IsFtps)

	// Service 2: NIST 800-171 compliance
	log.Println("Connecting to compliance service...")
	nistResult, err := checkNISTCompliance(ctx, diagResult)
	if err != nil {
		log.Fatalf("NIST compliance check failed: %v", err)
	}
	log.Printf("Compliance check complete: %v", nistResult.ComplianceScore)

	// Service 3: PDF report
	log.Println("Generating PDF report...")
	pdfResult, err := generateReport(ctx, diagResult, nistResult, owaspResult)
	if err != nil {
		log.Fatalf("PDF generation failed: %v", err)
	}

	log.Printf("=== Report Generated ===")
	log.Printf("Output: %s", func() string {
		if nistResult.OverallCompliant && owaspResult.OverallCompliant {
			return "COMPLIANT"
		}
		return "NON-COMPLIANT - Review findings immediately"
	}())
}

func getDiagnostics(ctx context.Context) (*DiagnosticsResponse, error) {
	conn, err := grpc.NewClient(ctx, diagAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("did not connect: %w", err)
	}
	defer func(conn *grpc.ClientConn) {
		err := conn.Close()
		if err != nil {
			log.Fatalf("failed to close connection: %v", err)
		}
	}(conn)

	client := NewDiagnosticServiceClient(conn)

	req := &DiagnosticsRequest{
		TargetHost:        "localhost",
		IncludePowershell: true,
	}

	return client.RunFTDiagnostics(ctx, req)
}

func checkNISTCompliance(ctx context.Context, diag *DiagnosticsResponse) (*ComplianceCheckResponse, error) {
	conn, err := grpc.NewClient(complianceAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("did not connect: %w", err)
	}
	defer func(conn *grpc.ClientConn) {
		err := conn.Close()
		if err != nil {
			log.Fatalf("failed to close connection: %v", err)
		}
	}(conn)

	client := compliancepb.NewComplianceServiceClient(conn)

	owasp := &compliancepb.OWASPSignals{
		HasFileUpload:          true,
		RequiresAuthentication: !diag.FtpConfig.AnonymousAccess,
		ValidatesFileTypes:     false,
		ScansForViruses:        false,
	}

	// Map the diagnostic results to compliance check
	req := &ComplianceCheckRequest{
		ServiceName:        diag.FtpConfig.ServiceName,
		IsEncrypted:        diag.FtpConfig.IsFtps,
		EncryptionStandard: mapTLSToStandard(diag.FtpConfig.TlsVersion),
		FipsValidated:      diag.FtpConfig.FipsCompliant == "true",
		AnonymousAccess:    diag.FtpConfig.AnonymousAccess,
	}

	return client.CheckNIST800171(ctx, req)
}
