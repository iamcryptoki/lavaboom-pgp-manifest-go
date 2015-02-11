package main

import (
	"bytes"
	"crypto/sha256"
	"flag"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/blang/semver"
	"github.com/dchest/uniuri"
	"github.com/lavab/pgp-manifest-go"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
)

const emailTemplate = `From: {{.From}}
To: {{.To}}{{if ne .CC "" }}
Cc: {{.CC}}{{end}}
Subject: Encrypted message ({{.ID}})
Content-Type: multipart/mixed; boundary="{{.Boundary1}}"

--{{.Boundary1}}
Content-Type: multipart/alternative; boundary="{{.Boundary2}}"

--{{.Boundary2}}
Content-Type: application/pgp-encrypted

{{.Body}}
--{{.Boundary2}}
Content-Type: text/html; charset='utf-8'

<!DOCTYPE html>
<html>
<body>
<p>This is an encrypted email, <a href="http://example.org/#id">
open it here if you email client doesn't support it</a></p>
</body>
</html>

--{{.Boundary2}}
Content-Type: text/plain; charset='utf-8'

This is an encrypted email, open it here if your email doesn't
support it:

http://example.org/#id
{{range .Attachments}}--{{$.Boundary1}}
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="{{.ID}}.pgp"

{{.Body}}
{{end}}
--{{.Boundary1}}
Content-Type: application/x-pgp-manifest+json
Content-Disposition: attachment; filename="manifest.pgp"

{{.Manifest}}
`

type templateInput struct {
	From        string
	To          string
	CC          string
	ID          string
	Body        string
	Boundary1   string
	Boundary2   string
	Manifest    string
	Attachments []*templateAttachment
}

type templateAttachment struct {
	ID   string
	Body string
}

var (
	publicKey       = flag.String("public-key", "", "Path to the PGP private key")
	from            = flag.String("from", "sender@example.org", "Sender of the email")
	to              = flag.String("to", "recipient@example.org", "Recipient of the email")
	cc              = flag.String("cc", "", "Carbon copy recipient")
	subject         = flag.String("subject", "Very secret email", "Subject of the email")
	bodyPath        = flag.String("body-path", "", "Path to the file containing the body text")
	attachmentPaths = flag.String("attachments", "", "Comma-seperated list of paths to attachments")
)

func main() {
	// Parse the flags
	flag.Parse()

	// Put data into the template
	tmpl := template.Must(template.New("email").Parse(emailTemplate))

	// Open the public key
	publicKeyFile, err := os.Open(*publicKey)
	if err != nil {
		log.Fatal(err)
	}

	// Parse it
	entityList, err := openpgp.ReadArmoredKeyRing(publicKeyFile)
	if err != nil {
		log.Fatal(err)
	}

	// Public key should be the first entity
	publicKey := entityList[0]

	// Prepare the template imput
	input := &templateInput{
		ID:        uniuri.New(),
		From:      *from,
		To:        *to,
		CC:        *cc,
		Boundary1: uniuri.New(),
		Boundary2: uniuri.New(),
	}

	// Prepare a new manifest
	man := &manifest.Manifest{
		Version: semver.Version{1, 0, 0, nil, nil},
		From:    *from,
		To:      *to,
		CC:      *cc,
		Subject: *subject,
		Parts:   []*manifest.Part{},
	}

	// Read the body file
	body, err := ioutil.ReadFile(*bodyPath)
	if err != nil {
		log.Fatal(err)
	}

	// Encrypt the body
	bodyEncryptionOutput := &bytes.Buffer{}
	bodyEncryptionInput, err := openpgp.Encrypt(bodyEncryptionOutput, []*openpgp.Entity{publicKey}, nil, nil, nil)
	if err != nil {
		log.Fatal(err)
	}

	// Write the body into the encrypting mechanism
	if _, err = bodyEncryptionInput.Write(body); err != nil {
		log.Fatal(err)
	}

	// Close the input
	if err = bodyEncryptionInput.Close(); err != nil {
		log.Fatal(err)
	}

	// Armor the encrypted output
	bodyArmoredOutput := &bytes.Buffer{}
	bodyArmoredInput, err := armor.Encode(bodyArmoredOutput, "PGP MESSAGE", map[string]string{
		"Version": "github.com/lavaboom/pgp-manifest-go/cmd/generator",
	})
	if err != nil {
		log.Fatal(err)
	}
	if _, err = io.Copy(bodyArmoredInput, bodyEncryptionOutput); err != nil {
		log.Fatal(err)
	}
	if err = bodyArmoredInput.Close(); err != nil {
		log.Fatal(err)
	}

	// Put the body into the template input
	input.Body = bodyArmoredOutput.String()

	if *attachmentPaths != "" {
		// Prepare the result attachments array
		attachments := []*templateAttachment{}

		// Read and encrypt all attachments
		attachmentParts := strings.Split(*attachmentPaths, ",")
		for _, part := range attachmentParts {
			// Read the file
			file, err := ioutil.ReadFile(part)
			if err != nil {
				log.Fatal(err)
			}

			// Create a new OpenPGP message
			encryptedOutput := &bytes.Buffer{}
			encryptedInput, err := openpgp.Encrypt(encryptedOutput, []*openpgp.Entity{publicKey}, nil, nil, nil)
			if err != nil {
				log.Fatal(err)
			}

			// Copy the file into the encryption reader
			if _, err = encryptedInput.Write(file); err != nil {
				log.Fatal(err)
			}

			// Close the reader
			if err = encryptedInput.Close(); err != nil {
				log.Fatal(err)
			}

			armoredOutput := &bytes.Buffer{}
			armoredInput, err := armor.Encode(armoredOutput, "PGP MESSAGE", map[string]string{
				"Version": "github.com/lavaboom/pgp-manifest-go/cmd/generator",
			})
			if err != nil {
				log.Fatal(err)
			}
			if _, err = io.Copy(armoredInput, encryptedOutput); err != nil {
				log.Fatal(err)
			}
			if err = armoredInput.Close(); err != nil {
				log.Fatal(err)
			}

			// Generate a ID for the attachment
			id := uniuri.New()

			// Put the result into the attachments slice
			attachments = append(attachments, &templateAttachment{
				ID:   id,
				Body: armoredOutput.String(),
			})

			// Calculate the hashsum of the file
			hash := sha256.Sum256(file)

			// Put the attachment info into the manifest
			man.Parts = append(man.Parts, &manifest.Part{
				ID:       id,
				Hash:     string(hash[:]),
				Filename: filepath.Base(part),
			})
		}

		// Put attachments into the template input
		input.Attachments = attachments
	}

	// Encode the manifest
	encodedManifest, err := manifest.Write(man)
	if err != nil {
		log.Fatal(err)
	}

	// Encrypt the manifest
	manifestEncryptedOutput := &bytes.Buffer{}
	manifestEncryptedInput, err := openpgp.Encrypt(manifestEncryptedOutput, []*openpgp.Entity{publicKey}, nil, nil, nil)
	if err != nil {
		log.Fatal(err)
	}
	if _, err = manifestEncryptedInput.Write(encodedManifest); err != nil {
		log.Fatal(err)
	}
	if err = manifestEncryptedInput.Close(); err != nil {
		log.Fatal(err)
	}

	manifestArmoredOutput := &bytes.Buffer{}
	manifestArmoredInput, err := armor.Encode(manifestArmoredOutput, "PGP MESSAGE", map[string]string{
		"Version": "github.com/lavaboom/pgp-manifest-go/cmd/generator",
	})
	if err != nil {
		log.Fatal(err)
	}
	if _, err = io.Copy(manifestArmoredInput, manifestEncryptedOutput); err != nil {
		log.Fatal(err)
	}
	if err = manifestArmoredInput.Close(); err != nil {
		log.Fatal(err)
	}

	input.Manifest = manifestArmoredOutput.String()

	// Execute the template input
	if err = tmpl.Execute(os.Stdout, input); err != nil {
		log.Fatal(err)
	}
}
