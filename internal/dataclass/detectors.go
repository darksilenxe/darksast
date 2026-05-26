// Package dataclass implements a Bearer-style "data inventory" pass that
// reports where sensitive data types appear in source code, independent
// of vulnerability findings. Detection is pattern-based (regex over file
// text), so the same engine works across every language the scanner
// already supports.
package dataclass

import (
	"regexp"
	"strings"
)

// Detector describes one sensitive data type. Identifier patterns
// match symbol names (variables, struct fields, object keys, function
// params), while literal patterns match the textual shape of the value
// itself (e.g. a literal email address inside a quoted string).
type Detector struct {
	// ID is a stable identifier emitted in reports, similar to a rule ID.
	ID string
	// Category groups related data types (e.g. "Personal Data",
	// "Financial", "Authentication", "Technical").
	Category string
	// DataType is a human-readable label (e.g. "Email Address").
	DataType string
	// Severity hints at the impact of exposing this data type. Defaults
	// to "MEDIUM" when empty.
	Severity string
	// IdentifierPatterns match identifier-shaped tokens. Each entry is a
	// case-insensitive regex anchored with word boundaries at runtime.
	IdentifierPatterns []string
	// LiteralPatterns match the literal value's textual shape (e.g. an
	// RFC-5322-ish email regex). Patterns are used as-is without
	// additional anchoring.
	LiteralPatterns []string

	idRegex      []*regexp.Regexp
	literalRegex []*regexp.Regexp
}

// compile lazily builds the detector's compiled regexes. The returned
// error stops scanner startup so misconfigured detectors fail loudly
// rather than silently producing no inventory.
func (d *Detector) compile() error {
	if d.idRegex == nil && len(d.IdentifierPatterns) > 0 {
		d.idRegex = make([]*regexp.Regexp, 0, len(d.IdentifierPatterns))
		for _, p := range d.IdentifierPatterns {
			expr := "(?i)\\b(?:" + p + ")\\b"
			re, err := regexp.Compile(expr)
			if err != nil {
				return err
			}
			d.idRegex = append(d.idRegex, re)
		}
	}
	if d.literalRegex == nil && len(d.LiteralPatterns) > 0 {
		d.literalRegex = make([]*regexp.Regexp, 0, len(d.LiteralPatterns))
		for _, p := range d.LiteralPatterns {
			re, err := regexp.Compile(p)
			if err != nil {
				return err
			}
			d.literalRegex = append(d.literalRegex, re)
		}
	}
	return nil
}

// EffectiveSeverity returns the detector's severity, defaulting to MEDIUM.
func (d *Detector) EffectiveSeverity() string {
	sev := strings.ToUpper(strings.TrimSpace(d.Severity))
	switch sev {
	case "LOW", "MEDIUM", "HIGH", "CRITICAL":
		return sev
	}
	return "MEDIUM"
}

// BuiltinDetectors returns a fresh copy of the default detector set
// covering the common Bearer-style categories. Callers receive a new
// slice on every call so compiled regex state is not shared across
// scans.
func BuiltinDetectors() []Detector {
	return []Detector{
		// --- Personal Data ---
		{
			ID:       "DATA-EMAIL",
			Category: "Personal Data",
			DataType: "Email Address",
			Severity: "MEDIUM",
			IdentifierPatterns: []string{
				`e?_?mail(?:_?address)?`,
				`user_?email`,
				`contact_?email`,
				`recipient_?email`,
				`sender_?email`,
				`from_?email`,
				`to_?email`,
			},
			LiteralPatterns: []string{
				`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`,
			},
		},
		{
			ID:       "DATA-PHONE-NUMBER",
			Category: "Personal Data",
			DataType: "Phone Number",
			Severity: "MEDIUM",
			IdentifierPatterns: []string{
				`phone(?:_?number)?`,
				`mobile(?:_?number)?`,
				`tel(?:ephone)?(?:_?number)?`,
				`cell(?:_?phone)?`,
				`fax(?:_?number)?`,
			},
		},
		{
			ID:       "DATA-PERSON-NAME",
			Category: "Personal Data",
			DataType: "Person Name",
			Severity: "MEDIUM",
			IdentifierPatterns: []string{
				`first_?name`,
				`last_?name`,
				`middle_?name`,
				`full_?name`,
				`given_?name`,
				`family_?name`,
				`maiden_?name`,
				`surname`,
				`display_?name`,
			},
		},
		{
			ID:       "DATA-POSTAL-ADDRESS",
			Category: "Personal Data",
			DataType: "Postal Address",
			Severity: "MEDIUM",
			IdentifierPatterns: []string{
				`street_?address`,
				`mailing_?address`,
				`billing_?address`,
				`shipping_?address`,
				`home_?address`,
				`postal_?address`,
				`zip_?code`,
				`postal_?code`,
				`address_?line[_-]?\d?`,
			},
		},
		{
			ID:       "DATA-DATE-OF-BIRTH",
			Category: "Personal Data",
			DataType: "Date of Birth",
			Severity: "HIGH",
			IdentifierPatterns: []string{
				`date_?of_?birth`,
				`birth_?date`,
				`birthday`,
				`dob`,
			},
		},
		{
			ID:       "DATA-GENDER",
			Category: "Personal Data",
			DataType: "Gender",
			Severity: "MEDIUM",
			IdentifierPatterns: []string{
				`gender`,
				`pronouns`,
			},
		},
		{
			ID:       "DATA-NATIONALITY",
			Category: "Personal Data",
			DataType: "Nationality",
			Severity: "MEDIUM",
			IdentifierPatterns: []string{
				`nationality`,
				`citizenship`,
				`country_?of_?origin`,
			},
		},
		{
			ID:       "DATA-GEOLOCATION",
			Category: "Personal Data",
			DataType: "Geolocation",
			Severity: "HIGH",
			IdentifierPatterns: []string{
				`latitude`,
				`longitude`,
				`geo_?location`,
				`gps_?coordinates?`,
				`lat_?long`,
			},
		},

		// --- Government / National Identifiers ---
		{
			ID:       "DATA-SSN",
			Category: "Personal Data",
			DataType: "Social Security Number",
			Severity: "CRITICAL",
			IdentifierPatterns: []string{
				`ssn`,
				`social_?security(?:_?number)?`,
				`tax_?id`,
				`national_?id`,
				`itin`,
			},
			// US SSN: 3-2-4 digits with dashes.
			LiteralPatterns: []string{
				`\b\d{3}-\d{2}-\d{4}\b`,
			},
		},
		{
			ID:       "DATA-PASSPORT-NUMBER",
			Category: "Personal Data",
			DataType: "Passport Number",
			Severity: "CRITICAL",
			IdentifierPatterns: []string{
				`passport(?:_?number)?`,
				`passport_?no`,
			},
		},
		{
			ID:       "DATA-DRIVERS-LICENSE",
			Category: "Personal Data",
			DataType: "Drivers License",
			Severity: "HIGH",
			IdentifierPatterns: []string{
				`drivers?_?license(?:_?number)?`,
				`driving_?license(?:_?number)?`,
				`license_?number`,
			},
		},

		// --- Financial ---
		{
			ID:       "DATA-CREDIT-CARD",
			Category: "Financial",
			DataType: "Credit Card Number",
			Severity: "CRITICAL",
			IdentifierPatterns: []string{
				`credit_?card(?:_?number)?`,
				`card_?number`,
				`cc_?number`,
				`primary_?account_?number`,
			},
			// 13-19 digit Visa/MC/Amex/Discover/JCB shapes; identifier
			// detection covers the structured field case.
			LiteralPatterns: []string{
				`\b(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|3[47]\d{13}|6011\d{12}|(?:2131|1800|35\d{3})\d{11})\b`,
			},
		},
		{
			ID:       "DATA-CVV",
			Category: "Financial",
			DataType: "Card Verification Value",
			Severity: "CRITICAL",
			IdentifierPatterns: []string{
				`cvv\d?`,
				`cvc\d?`,
				`csc`,
				`card_?security_?code`,
				`card_?verification_?(?:value|code)`,
			},
		},
		{
			ID:       "DATA-IBAN",
			Category: "Financial",
			DataType: "Bank Account / IBAN",
			Severity: "HIGH",
			IdentifierPatterns: []string{
				`iban`,
				`bank_?account(?:_?number)?`,
				`account_?number`,
				`routing_?number`,
				`swift_?code`,
				`bic`,
			},
			LiteralPatterns: []string{
				`\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b`,
			},
		},

		// --- Health ---
		{
			ID:       "DATA-HEALTH",
			Category: "Health",
			DataType: "Health / Medical Data",
			Severity: "CRITICAL",
			IdentifierPatterns: []string{
				`medical_?record(?:_?number)?`,
				`patient_?id`,
				`diagnosis`,
				`prescription`,
				`health_?insurance(?:_?number)?`,
				`blood_?type`,
				`disability`,
			},
		},

		// --- Authentication / Secrets ---
		{
			ID:       "DATA-PASSWORD",
			Category: "Authentication",
			DataType: "Password",
			Severity: "HIGH",
			IdentifierPatterns: []string{
				`password`,
				`passwd`,
				`pwd`,
				`passphrase`,
				`secret_?phrase`,
			},
		},
		{
			ID:       "DATA-API-TOKEN",
			Category: "Authentication",
			DataType: "API Token / Key",
			Severity: "HIGH",
			IdentifierPatterns: []string{
				`api_?key`,
				`api_?token`,
				`access_?token`,
				`refresh_?token`,
				`auth_?token`,
				`bearer_?token`,
				`session_?token`,
				`client_?secret`,
				`private_?key`,
			},
		},
		{
			ID:       "DATA-JWT",
			Category: "Authentication",
			DataType: "JSON Web Token",
			Severity: "HIGH",
			IdentifierPatterns: []string{
				`jwt(?:_?token)?`,
				`id_?token`,
			},
			LiteralPatterns: []string{
				`\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b`,
			},
		},

		// --- Technical / Device ---
		{
			ID:       "DATA-IP-ADDRESS",
			Category: "Technical",
			DataType: "IP Address",
			Severity: "LOW",
			IdentifierPatterns: []string{
				`ip_?address`,
				`client_?ip`,
				`remote_?ip`,
				`source_?ip`,
				`peer_?ip`,
			},
			LiteralPatterns: []string{
				`\b(?:25[0-5]|2[0-4]\d|[01]?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d?\d)){3}\b`,
			},
		},
		{
			ID:       "DATA-MAC-ADDRESS",
			Category: "Technical",
			DataType: "MAC Address",
			Severity: "LOW",
			IdentifierPatterns: []string{
				`mac_?address`,
			},
			LiteralPatterns: []string{
				`\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b`,
			},
		},
		{
			ID:       "DATA-DEVICE-ID",
			Category: "Technical",
			DataType: "Device Identifier",
			Severity: "LOW",
			IdentifierPatterns: []string{
				`device_?id`,
				`device_?identifier`,
				`udid`,
				`imei`,
				`advertising_?id`,
				`idfa`,
				`aaid`,
			},
		},
	}
}
