package main

import (
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"mime"
	"mime/multipart"
	"net/mail"
	"os"
	"strings"

	"github.com/lavab/pgp-manifest-go"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
)

var (
	privateKey = flag.String("private-key", "", "Path to the PGP private key")
	password   = flag.String("password", "", "Password to the key")
	input      = flag.String("input", "", "Path to the input")
)

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

	// Parse the flags
	flag.Parse()

	// Open the private key file
	privateKeyFile, err := os.Open(*privateKey)
	if err != nil {
		log.Fatal(err)
	}

	// Parse the file
	keyring, err := openpgp.ReadArmoredKeyRing(privateKeyFile)
	if err != nil {
		log.Fatal(err)
	}

	// Open the email file
	emailFile, err := os.Open(*input)
	if err != nil {
		log.Fatal(err)
	}

	// Parse the email
	rootEmail, err := mail.ReadMessage(emailFile)
	if err != nil {
		log.Fatal(err)
	}

	// Print some data
	fmt.Printf("Original From: %s\n", rootEmail.Header.Get("from"))
	fmt.Printf("Original To: %s\n", rootEmail.Header.Get("to"))
	fmt.Printf("Original Cc: %s\n", rootEmail.Header.Get("cc"))
	fmt.Printf("Original Subject: %s\n", rootEmail.Header.Get("subject"))

	// Seperate original root headers from the rest
	fmt.Print("\n")

	// Get the Content-Type
	contentType := rootEmail.Header.Get("content-type")

	// Get the boundary
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		log.Fatal(err)
	}

	// Parse the body
	if !strings.HasPrefix(mediaType, "multipart/") {
		log.Fatal("Email isn't multipart")
	}

	// Find the manifest and decode it
	var man *manifest.Manifest

	// Create a new multipart reader
	rootReader := multipart.NewReader(rootEmail.Body, params["boundary"])

	for {
		part, err := rootReader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatal(err)
		}

		// Parse the email
		email, err := mail.ReadMessage(part)
		if err != nil {
			log.Fatal(err)
		}

		mediaType, params, err := mime.ParseMediaType(email.Header.Get("content-type"))
		if err != nil {
			log.Fatal(err)
		}

		// We found the body
		if mediaType == "multipart/alternative" {
			bodyReader := multipart.NewReader(part, params["boundary"])
			for {
				part, err := bodyReader.NextPart()
				if err == io.EOF {
					break
				}
				if err != nil {
					log.Fatal(err)
				}

				// Parse the part
				email, err := mail.ReadMessage(part)
				if err != nil {
					log.Fatal(err)
				}

				// Parse the content type
				mediaType, _, err := mime.ParseMediaType(email.Header.Get("content-type"))
				if err != nil {
					log.Fatal(err)
				}

				if mediaType == "application/x-pgp-manifest+json" {
					fmt.Println("Found the manifest.")

					block, err := armor.Decode(email.Body)
					if err != nil {
						log.Fatal(err)
					}

					md, err := openpgp.ReadMessage(
						block.Body,
						keyring,
						func(keys []openpgp.Key, symmetric bool) ([]byte, error) {
							return []byte(*password), nil
						},
						nil,
					)
					if err != nil {
						log.Fatal(err)
					}

					cleartext, err := ioutil.ReadAll(md.UnverifiedBody)
					if err != nil {
						log.Fatal(err)
					}

					man, err = manifest.Parse(cleartext)
					if err != nil {
						log.Fatal(err)
					}

					break
				}
			}
		}
	}

	// Show manifest data
	fmt.Print("Manifest headers:\n")
	for key, value := range man.Headers {
		fmt.Printf("\t%s: %s\n", key, value)
	}
	fmt.Print("Email parts in the manifest:\n")
	for _, part := range man.Parts {
		fmt.Printf("\t- Hash: %s\n", part.Hash)
		fmt.Printf("\t- ID: %s\n", part.ID)
		fmt.Printf("\t- Filename: %s\n", part.Filename)
	}
}
