package manifest

import (
	"github.com/blang/semver"
)

type Manifest struct {
	Version semver.Version `json:"version"`

	From        string `json:"-"`
	To          string `json:"-"`
	CC          string `json:"-"`
	Subject     string `json:"-"`
	ContentType string `json:"-"`

	Headers map[string]string `json:"headers"`
	Parts   []*Part           `json:"part,omitempty"`
}

type Part struct {
	Hash        string `json:"hash"`
	ID          string `json:"id"`
	ContentType string `json:"content-type"`
	Filename    string `json:"filename,omitempty"`
}
