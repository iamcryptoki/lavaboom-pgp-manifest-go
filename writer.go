package manifest

import (
	"encoding/json"
	"strings"
)

func Write(input *Manifest) ([]byte, error) {
	if input.Headers == nil {
		input.Headers = map[string]string{}
	} else {
		for key, value := range input.Headers {
			input.Headers[key] = strings.ToLower(value)
		}
	}

	if input.From != "" {
		input.Headers["from"] = input.From
	}

	if input.To != "" {
		input.Headers["to"] = input.To
	}

	if input.CC != "" {
		input.Headers["cc"] = input.CC
	}

	if input.Subject != "" {
		input.Headers["subject"] = input.Subject
	}

	if input.ContentType != "" {
		input.Headers["content-type"] = input.ContentType
	}

	return json.Marshal(input)
}
