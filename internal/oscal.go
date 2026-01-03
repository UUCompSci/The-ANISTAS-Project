package internal

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// OscalRoot represents the top-level OSCAL Assessment Results object
type OscalRoot struct {
	AssessmentResults AssessmentResults `json:"assessment-results"`
}

type AssessmentResults struct {
	UUID     string   `json:"uuid"`
	Metadata Metadata `json:"metadata"`
	Results  []Result `json:"results"`
}

type Metadata struct {
	Title        string    `json:"title"`
	LastModified time.Time `json:"last-modified"`
	Version      string    `json:"version"`
	OscalVersion string    `json:"oscal-version"`
}

type Result struct {
	UUID        string        `json:"uuid"`
	Title       string        `json:"title"`
	Description string        `json:"description"`
	Start       time.Time     `json:"start"`
	Findings    []Finding     `json:"findings,omitempty"`
	Observations []Observation `json:"observations,omitempty"`
}

type Finding struct {
	UUID        string          `json:"uuid"`
	Title       string          `json:"title"`
	Description string          `json:"description"`
	Target      FindingTarget   `json:"target"`
	RelatedObservations []RelatedObservation `json:"related-observations,omitempty"`
}

type FindingTarget struct {
	Type     string `json:"type"`
	TargetID string `json:"target-id"` // This will store the NIST Control ID (e.g., "3.1.1")
	Status   Status `json:"status"`
}

type Status struct {
	State string `json:"state"` // satisfied, not-satisfied
}

type Observation struct {
	UUID        string   `json:"uuid"`
	Description string   `json:"description"`
	Methods     []string `json:"methods"`
	Collected   time.Time `json:"collected"`
}

type RelatedObservation struct {
	ObservationUUID string `json:"observation-uuid"`
}

// GenerateOscalSAR converts internal AssessmentResults to an OSCAL SAR structure
func GenerateOscalSAR(auditResults []AssessmentResult) (OscalRoot, error) {
	resultUUID := uuid.New().String()
	
	// Initialize the root structure
	oscal := OscalRoot{
		AssessmentResults: AssessmentResults{
			UUID: uuid.New().String(),
			Metadata: Metadata{
				Title:        "NIST 800-171 Assessment Results",
				LastModified: time.Now(),
				Version:      "1.0.0",
				OscalVersion: "1.1.2",
			},
			Results: []Result{
				{
					UUID:        resultUUID,
					Title:       "Automated DB Audit",
					Description: "Audit performed by Go tool",
					Start:       time.Now(),
					Findings:    []Finding{},
					Observations: []Observation{},
				},
			},
		},
	}

	resultEntry := &oscal.AssessmentResults.Results[0]

	for _, ar := range auditResults {
		obsUUID := uuid.New().String()
		
		// 1. Create an Observation (The raw evidence)
		obs := Observation{
			UUID:        obsUUID,
			Description: ar.Evidence,
			Methods:     []string{"TEST"},
			Collected:   time.Now(),
		}
		resultEntry.Observations = append(resultEntry.Observations, obs)

		// 2. Create a Finding (The conclusion: Pass/Fail)
		state := "not-satisfied"
		if ar.Status == "Pass" {
			state = "satisfied"
		}

		finding := Finding{
			UUID:        uuid.New().String(),
			Title:       "Validation of " + ar.ControlID,
			Description: "Automated validation status: " + ar.Status,
			Target: FindingTarget{
				Type:     "objective-id", 
				TargetID: ar.ControlID,
				Status: Status{
					State: state,
				},
			},
			RelatedObservations: []RelatedObservation{
				{ObservationUUID: obsUUID},
			},
		}
		resultEntry.Findings = append(resultEntry.Findings, finding)
	}

	return oscal, nil
}

// Helper to print JSON (for debugging or CLI output)
func ToJSON(v interface{}) (string, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}
