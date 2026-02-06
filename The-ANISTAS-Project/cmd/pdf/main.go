// PDF Service - Microservice 3
// Generates compliance reports

package main

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	"log"
	"net"
	"os/exec"
	"time"

	"github.com/SebastiaanKlippert/go-wkhtmltopdf"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/UUCompSci/The-ANISTAS-Project/internal/proto"
)

type reportServer struct {
	pb.UnimplementedReportServiceServer
}

// GeneratePDF creates a PDF report from diagnostic and compliance data
func (s *reportServer) GeneratePDF(ctx context.Context, req *pb.GeneratePDFRequest) (*pb.GeneratePDFResponse, error) {
	log.Printf("Generating PDF report: %s", req.ReportTitle)

	// Generate HTML from a template
	html, err := generateHTML(req)
	if err != nil {
		return nil, fmt.Errorf("html generation failed: %w", err)
	}

	// Initialize wkhtmltopdf generator
	pdfg, err := wkhtmltopdf.NewPDFGenerator()
	if err != nil {
		return nil, fmt.Errorf("pdf generator init failed: %w", err)
	}

	// Add HTML page
	pdfg.AddPage(wkhtmltopdf.NewPageReader(bytes.NewBufferString(html)))

	// Set PDF options
	pdfg.Dpi.Set(300)
	pdfg.Orientation.Set(wkhtmltopdf.OrientationPortrait)
	pdfg.PageSize.Set(wkhtmltopdf.PageSizeA4)

	// Generate PDF
	if err := pdfg.Create(); err != nil {
		return nil, fmt.Errorf("pdf creation failed: %w", err)
	}

	// Save to file
	outputPath := fmt.Sprintf("compliance-report-%d.pdf", time.Now().Unix())
	if err := pdfg.WriteFile(outputPath); err != nil {
		return nil, fmt.Errorf("pdf write failed: %w", err)
	}

	// Return bytes for potential further processing
	return &pb.GeneratePDFResponse{
		Success:    true,
		PdfBytes:   pdfg.Bytes(),
		OutputPath: outputPath,
	}, nil
}

// generateHTML creates an HTML report template with all findings
func generateHTML(req *pb.GeneratePDFRequest) (string, error) {
	const tmpl = `
<!DOCTYPE html>
<html>
<head>
    <title>{{.Title}}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .header { background: #1e3a5f; color: white; padding: 20px; }
        .section { margin: 20px 0; border: 1px solid #ddd; padding: 15px; }
        .finding { margin: 10px 0; padding: 10px; border-left: 4px solid; }
        .compliant { border-color: #28a745; background: #d4edda; }
        .non-compliant { border-color: #dc3545; background: #f8d7da; }
        .critical { color: #dc3545; font-weight: bold; }
        .score { font-size: 24px; text-align: center; padding: 20px; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { padding: 8px; border: 1px solid #ddd; text-align: left; }
        th { background: #f2f2f2; }
    </style>
</head>
<body>
    <div class="header">
        <h1>{{.Title}}</h1>
        <p>Organization: {{.Organization}} | Prepared by: {{.PreparedBy}}</p>
        <p>Generated: {{.GeneratedAt}}</p>
    </div>

    <div class="section">
        <h2>Executive Summary</h2>
        <div class="score">
            Compliance Score: {{.NistData.ComplianceScore}}%
            {{if .NistData.OverallCompliant}}
                <span style="color: green;">COMPLIANT</span>
            {{else}}
                <span style="color: red;">NON-COMPLIANT</span>
            {{end}}
        </div>
    </div>

    <div class="section">
        <h2>System Diagnostic Results</h2>
        <table>
            <tr><th>Service</th><th>Status</th><th>Encryption</th><th>Port</th></tr>
            <tr>
                <td>{{.DiagData.FtpConfig.ServiceName}}</td>
                <td>{{if .DiagData.FtpConfig.IsRunning}}Running{{else}}Stopped{{end}}</td>
                <td>{{if .DiagData.FtpConfig.IsFtps}}FTPS ({{.DiagData.FtpConfig.TlsVersion}}){{else}}None{{end}}</td>
                <td>{{.DiagData.FtpConfig.Port}}</td>
            </tr>
        </table>
        <p>FIPS Compliant: {{.DiagData.FtpConfig.FipsCompliant}}</p>
        <p>Anonymous Access: {{if .DiagData.FtpConfig.AnonymousAccess}}Enabled (DANGER){{else}}Disabled{{end}}</p>
    </div>

    <div class="section">
        <h2>NIST 800-171 Findings</h2>
        {{range .NistData.Findings}}
        <div class="finding {{if .Compliant}}compliant{{else}}non-compliant{{end}}">
            <strong>Control {{.ControlId}}</strong> 
            <span class="{{if eq .Severity "CRITICAL"}}critical{{end}}">[{{.Severity}}]</span><br>
            {{.Description}}<br>
            <em>Status: {{if .Compliant}}PASS{{else}}FAIL{{end}}</em><br>
            {{if not .Compliant}}
                <strong>Remediation:</strong> {{.Remediation}}<br>
                <em>Rationale: {{.Rationale}}</em>
            {{end}}
        </div>
        {{end}}
    </div>

    <div class="section">
        <h2>Administrative Notes</h2>
        <p>This report was generated with elevated privileges to access system configuration.</p>
        <p>Raw diagnostic data available separately for audit trail.</p>
    </div>
</body>
</html>
`

	type templateData struct {
		Title        string
		Organization string
		PreparedBy   string
		GeneratedAt  string
		DiagData     *pb.DiagnosticsResponse
		NistData     *pb.ComplianceCheckResponse
	}

	data := templateData{
		Title:        req.ReportTitle,
		Organization: req.Organization,
		PreparedBy:   req.PreparedBy,
		GeneratedAt:  time.Now().Format("2006-01-02 15:04:05"),
		DiagData:     req.DiagData,
		NistData:     req.NistData,
	}

	t := template.Must(template.New("report").Parse(tmpl))
	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return "", err
	}

	return buf.String(), nil
}

func main() {
	// Verify wkhtmltopdf is installed
	if _, err := exec.LookPath("wkhtmltopdf"); err != nil {
		log.Fatal("wkhtmltopdf not found in PATH. Install from https://wkhtmltopdf.org/")
	}

	lis, err := net.Listen("tcp", ":50053")
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	s := grpc.NewServer(grpc.Creds(insecure.NewCredentials()))
	pb.RegisterReportServiceServer(s, &reportServer{})

	log.Printf("PDF Service listening on :50053")
	if err := s.Serve(lis); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}
