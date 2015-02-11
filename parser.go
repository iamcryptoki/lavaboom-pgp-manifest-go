package manifest

import (
	"encoding/json"
)

func Parse(input []byte) (*Manifest, error) {
	// Prepare a new manifest struct
	var manifest Manifest

	// Decode the input
	if err := json.Unmarshal(input, &manifest); err != nil {
		return nil, err
	}

	// Move the headers into the main manifest struct
	if val, ok := manifest.Headers["from"]; ok {
		manifest.From = val
	}
	if val, ok := manifest.Headers["to"]; ok {
		manifest.To = val
	}
	if val, ok := manifest.Headers["cc"]; ok {
		manifest.CC = val
	}
	if val, ok := manifest.Headers["subject"]; ok {
		manifest.Subject = val
	}
	if val, ok := manifest.Headers["content-type"]; ok {
		manifest.ContentType = val
	}

	return &manifest, nil
}
