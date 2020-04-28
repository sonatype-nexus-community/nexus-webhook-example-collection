package nexuswebhook

import (
	"time"
)

type SonatypeDate struct {
	time.Time
}

func (sd *SonatypeDate) UnmarshalJSON(input []byte) error {
	newTime, err := time.Parse(time.RFC3339, string(input))
	if err != nil {
		return err
	}

	sd.Time = newTime
	return nil
}

//  ApplicationEvaluation contains the information for Sonatype IQ server Application Evaluation hook event
type ApplicationEvaluationPayload struct {
	//Timestamp time.Time `json:"timestamp"`
	Timestamp             string `json:"timestamp"`
	Initiator             string `json:"initiator"`
	Id                    string `json:"id"`
	ApplicationEvaluation struct {
		PolicyEvaluationId string `json:"policyEvaluationId"`
		Stage              string `json:"stage"`
		OwnerId            string `json:"ownerId"`
		//EvaluationDate SonatypeDate `json:"evaluationDate"`
		EvaluationDate         string `json:"evaluationDate"`
		AffectedComponentCount int64  `json:"affectedComponentCount"`
		CriticalComponentCount int64  `json:"criticalComponentCount"`
		SevereComponentCount   int64  `json:"severeComponentCount"`
		ModerateComponentCount int64  `json:"moderateComponentCount"`
		Outcome                string `json:"outcome"`
	} `json:"applicationEvaluation"`
}

// PolicyManagementPayload contains the information for Sonatype IQ server Policy Management hook event
type PolicyManagementPayload struct {
	//Timestamp time.Time `json:"timestamp"`
	Timestamp string `json:"timestamp"`
	Initiator string `json:"initiator"`
	Id        string `json:"id"`
	Owner     struct {
		Id            string `json:"id"`
		PublicId      string `json:"publicId"`
		Name          string `json:"name"`
		ParentOwnerId string `json:"parentOwnerId"`
		Type          string `json:"type"`
		Tags          []struct {
			Id          string `json:"id"`
			Name        string `json:"name"`
			Description string `json:"description"`
			Color       string `json:"color"`
		} `json:"tags,omitempty"`
		Labels []struct {
			Id          string `json:"id"`
			Name        string `json:"name"`
			Description string `json:"description"`
			Color       string `json:"color"`
		} `json:"labes,omitempty"`
		LicenseThreatGroups []struct {
			Id          string `json:"id"`
			Name        string `json:"name"`
			ThreatLevel int64  `json:"threatLevel"`
		} `json:"licenseThreatGroups"`
		Policies []struct {
			Id          string `json:"id"`
			Name        string `json:"name"`
			ThreatLevel int64  `json:"threatLevel"`
		} `json:"policies"`
		Access []struct {
			Id      string `json:"id"`
			Name    string `json:"name"`
			Members []struct {
				Type string `json:"type"`
				Name string `json:"name"`
			} `json:"licenseThreatGroups"`
		} `json:"members"`
	} `json:"owner"`
}

// SecurityVulnerabilityOverrideManagementPayload contains the information for Sonatype IQ server Security Vulnerability Override Management Event hook event
type SecurityVulnerabilityOverrideManagementPayload struct {
	//Timestamp time.Time `json:"timestamp"`
	Timestamp                     string `json:"timestamp"`
	Initiator                     string `json:"initiator"`
	Id                            string `json:"id"`
	SecurityVulnerabilityOverride struct {
		Id          string `json:"id"`
		OwnerId     string `json:"ownerId"`
		Hash        string `json:"hash"`
		Source      string `json:"source"`
		ReferenceId string `json:"referenceId"`
		Status      string `json:"status"`
		Comment     string `json:"comment"`
	} `json:"securityVulnerabilityOverride"`
}

// LicenseOverrideManagementPayload contains the information for Sonatype IQ server License Override Management hook event
type LicenseOverrideManagementPayload struct {
	//Timestamp time.Time `json:"timestamp"`
	Timestamp       string `json:"timestamp"`
	Initiator       string `json:"initiator"`
	Id              string `json:"id"`
	LicenseOverride struct {
		Id                  string   `json:"id"`
		OwnerId             string   `json:"ownerId"`
		Status              string   `json:"status"`
		Comment             string   `json:"comment"`
		LicenseIds          []string `json:"licenseIds"`
		ComponentIdentifier struct {
			Format      string `json:"format"`
			Coordinates struct {
				ArtifactId string `json:"artifactId"`
				Classifier string `json:"classifier"`
				Extension  string `json:"extension"`
				GroupId    string `json:"groupId"`
				Version    string `json:"version"`
			} `json:"coordinates"`
		} `json:"componentIdentifier"`
	} `json:"licenseOverride"`
}
