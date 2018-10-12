package nexus-webhook-example-collection 

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
)

// parse errors
var (
	ErrEventNotSpecifiedToParse  = errors.New("no Event specified to parse")
	ErrInvalidHTTPMethod         = errors.New("invalid HTTP Method")
	ErrEventNotFound             = errors.New("event not defined to be parsed")
	ErrParsingPayload            = errors.New("error parsing payload")
	ErrMissingWebhookIdHeader    = errors.New("missing X-Nexus-Webhook-Id Header")
	ErrMissingSignatureHeader    = errors.New("missing X-Nexus-Webhook-Signature Header")
	ErrHMACVerificationFailed    = errors.New("HMAC verification failed")
)

// Event defines hook event type
type Event string

// Hook types
const (
	PolicyManagement                            Event = "iq:policyManagement"
	ApplicationEvaluation                       Event = "iq:applicationEvaluation"
	LicenseOverrideManagement                   Event = "iq:licenseOverrideManagement"
	SecurityVulnerabilityOverrideManagement     Event = "iq:securityVulnerabilityOverrideManagement"
)

// Option is a configuration option for the webhook
type Option func(*Webhook) error

// Options is a namespace var for configuration options
var Options = WebhookOptions{}

// WebhookOptions is a namespace for configuration option methods
type WebhookOptions struct{}

// Secret registers the Sonatype secret
func (WebhookOptions) Secret(secret string) Option {
	return func(hook *Webhook) error {
		hook.secret = secret
		return nil
	}
}

// Webhook instance contains all methods needed to process events
type Webhook struct {
	secret string
}

// New creates and returns a WebHook instance denoted by the Provider type
func New(options ...Option) (*Webhook, error) {
	hook := new(Webhook)
	for _, opt := range options {
		if err := opt(hook); err != nil {
			return nil, errors.New("Error applying Option")
		}
	}
	return hook, nil
}

// Parse verifies and parses the events specified and returns the payload object or an error
func (hook Webhook) Parse(r *http.Request, events ...Event) (interface{}, error) {
	defer func() {
		_, _ = io.Copy(ioutil.Discard, r.Body)
		_ = r.Body.Close()
	}()

	if len(events) == 0 {
		return nil, ErrEventNotSpecifiedToParse
	}
	if r.Method != http.MethodPost {
		return nil, ErrInvalidHTTPMethod
	}

	event := r.Header.Get("X-Nexus-Webhook-Id")
	if event == "" {
		return nil, ErrMissingWebhookIdHeader
	}
	SonatypeEvent := Event(event)

	var found bool
	for _, evt := range events {
		if evt == SonatypeEvent {
			found = true
			break
		}
	}
	// event not defined to be parsed
	if !found {
		return nil, ErrEventNotFound
	}

	payload, err := ioutil.ReadAll(r.Body)
	if err != nil || len(payload) == 0 {
		return nil, ErrParsingPayload
	}

	// If we have a Secret set, we should check it matches
	if len(hook.secret) > 0 {
		signature := r.Header.Get("X-Nexus-Webhook-Signature")
		if len(signature) == 0 {
			return nil, ErrMissingSignatureHeader
		}
		mac := hmac.New(sha1.New, []byte(hook.secret))
		_, _ = mac.Write(payload)
		expectedMAC := hex.EncodeToString(mac.Sum(nil))

		if !hmac.Equal([]byte(signature[5:]), []byte(expectedMAC)) {
			return nil, ErrHMACVerificationFailed
		}
	}

	switch SonatypeEvent {
	case PolicyManagement:
		var pl PolicyManagementPayload
		err = json.Unmarshal([]byte(payload), &pl)
		return pl, err
	case ApplicationEvaluation:
		var pl ApplicationEvaluationPayload
		err = json.Unmarshal([]byte(payload), &pl)
		return pl, err
	case LicenseOverrideManagement:
		var pl LicenseOverrideManagementPayload
		err = json.Unmarshal([]byte(payload), &pl)
		return pl, err
	case SecurityVulnerabilityOverrideManagement:
		var pl SecurityVulnerabilityOverrideManagementPayload
		err = json.Unmarshal([]byte(payload), &pl)
		return pl, err
	default:
		return nil, fmt.Errorf("unknown event %s", SonatypeEvent)
	}
}

