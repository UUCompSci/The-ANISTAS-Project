// Microservice two - the compliance service
// this runs the diagnostics report against NIST 800-171 using OWASP's framework

package main

import (
	"context"
	_ "fmt"
	"log"
	"net"
	_ "strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/UUCompSci/The-ANISTAS-Project/internal/proto"
)

type complianceServer struct {
	pb.UnimplementedComplianceServiceServer
}

// CHECK NIST SP 800-171
func (s *complianceServer) CheckNIST800171(ctx context.Context, req *pb.ComplianceCheckRequest) (*pb.ComplianceCheckresponse, error) {
	log.Printf("Evaluating compliance against NIST SP 800-171 for: %s", req, ServiceName)

	var findings []*pb.NISTFinding
	compliant := true
	score := 100.0

	// NIST SP 800-171 Control 3.13.8: Cryptographic protection during transmission
	control_3_13_8 := &pb.NISTFinding{
		ControlId:   "3.13.8",
		Description: "Implement cryptographic mechanisms to prevent unauthorized disclosure of CUI during transmission",
		Rationale:   "CUI must be encrypted in transit to prevent interception",
		Severity:    "CRITICAL",
		Remediation: "Enable FTPS (FTP over TLS) or replace with SFTP. Configure minimum TLS 1.2.",
	}

	if !req.IsEncrypted {
		control_3_13_8.Compliant = false
		compliant = false
		score -= 30.0
	} else {
		control_3_13_8.Compliant = true
	}
	findings = append(findings, control_3_13_8)

	// NIST 800-171 Control 3.13.11: FIPS-validated cryptography
	control_3_13_11 := &pb.NISTFinding{
		ControlId:   "3.13.11",
		Description: "Employ FIPS-validated cryptography when uesd to protect the confidentiality, integrity, or authenticity of information system components",
		Rationale:   "Only NIST CMVP-validated cryptographic modules may be used for the protection of CUI",
		Severity:    "HIGH",
		Remediation: "Enable FIPS mode in Windows (Local Security Policy) or use FIPS-validated TLS libraries.",
	}

	if !req.FipsValidated {
		control_3_13_11.Compliant = false
		compliant = false
		score -= 20.0
	} else {
		control_3_13_11.Compliant = true
	}
	findings = append(findings, control_3_13_11)

	// Control 3.5.1: Identify and authenticate system users, processes acting on behalf of users, and devices (e.g., printers, scanners, mobile devices, etc.)
	control_3_5_1 := &pb.NISTFinding{
		ControlId:   "3.5.1",
		Description: "Identify system users, processes acting on behalf of users, and devices (e.g., printers, scanners, mobile devices, etc.)",
		Compliant:   !req.AnonymousAccess,
		Severity:    "CRITICAL",
		Remediation: "Disable anonymous FTP access.",
		Rationale:   "Anonymous access prevents accountability and audit trails",
	}
	if !req.AnonymousAccess {
		compliant = false
		score -= 30.0
	} else {
		control_3_5_1.Compliant = true
	}
	findings = append(findings, control_3_5_1)

	// Ensuring the score never dips below 0
	if score < 0 {
		score = 0
	}

	return &pb.ComplianceCheckResponse{
		OverallCompliant: compliant,
		Findings:         findings,
		ComplianceScore:  score,
	}, nil
}

// Check that OWASP validates against the FTP reqs
func (s *complianceServer) CheckNIST(ctx context.Context, req *pb.NISTCheckRequest) (*pb.NISTCheckResponse, error) {
	log.Printf("Evaluating NIST compliance")

	var findings []*pb.NISTFinding
	compliant := true

	// File upload validation
	findings = append(findings, &pb.NISTFinding{
		Category:    "File Upload",
		Requirement: "Validate file types and extensions before processing",
		Compliant:   req.ValidatesFileTypes,
		RiskLevel:   "HIGH",
		Mitigation:  "Use a whitelist of allowed file types.",
	})
	if !req.ValidatesFileTypes {
		compliant = false
	} else {
		compliant = true
	}
	// Authentication
	findings = append(findings, &pb.OWASPFinding{
		Category:    "Authentication",
		Requirement: "Require authentication for all file transfer operations",
		Compliant:   req.RequiresAuthentication,
		RiskLevel:   "CRITICAL",
		Mitigation:  "Enforce MFA and session management",
	})
	if !req.RequiresAuthentication {
		compliant = false
	}

	// Malware scanning
	findings = append(findings, &pb.OWASPFinding{
		Category:    "Malware Defense",
		Requirement: "Scan uploaded files for malicious content",
		Compliant:   req.ScansForViruses,
		RiskLevel:   "HIGH",
		Mitigation:  "Integrate antivirus scanning before file storage/processing",
	})
	if !req.ScansForViruses {
		compliant = false
	}

	return &pb.OWASPCheckResponse{
		OverallCompliant: compliant,
		Findings:         findings,
	}, nil
}

func main() {
	lis, err := net.Listen("tcp", "50052")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	s := grpc.NewServer(grpc.Creds(insecure.NewCredentials()))
	pb.RegisterComplianceServiceServer(s, &complianceServer{})

	log.Printf("server listening at %v", lis.Addr())
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
