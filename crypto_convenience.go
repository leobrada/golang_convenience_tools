package convenience_tools

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"strings"
)

// X509 PART

// function unifies the loading of CA certificates
func LoadCACertificate(certfile string, certPool *x509.CertPool) error {
	caRoot, err := ioutil.ReadFile(certfile)
	if err != nil {
		return fmt.Errorf("loadCACertificate(): Loading CA certificate from %s error: %v", certfile, err)
	}

	certPool.AppendCertsFromPEM(caRoot)
	return nil
}

// function unifies the loading of X509 key pairs
func LoadX509KeyPair(certfile, keyfile string) (tls.Certificate, error) {
	keyPair, err := tls.LoadX509KeyPair(certfile, keyfile)
	if err != nil {
		return keyPair, fmt.Errorf("loadX509KeyPair(): critical error when loading X509KeyPair from %s and %s: %v", certfile, keyfile, err)
	}

	return keyPair, nil
}

// RSA PART

// ParseRsaPublicKeyFromPemFile() loads rsa.PublicKey from a PEM file
func ParseRsaPublicKeyFromPemFile(pubPEMLocation string) (*rsa.PublicKey, error) {
	// Read a file content and convert it to a PEM block
	pemBlock, err := readFirstPEMBlockFromFile(pubPEMLocation)
	if err != nil {
		return nil, fmt.Errorf("ParseRsaPublicKeyFromPemFile(): %w", err)
	}

	if !strings.Contains(pemBlock.Type, "PUBLIC KEY") {
		fmt.Printf("pemBlock.Type = %#v\n", pemBlock.Type)
		return nil, errors.New("ParseRsaPublicKeyFromPemFile(): provided file does not contain a PEM public key")
	}

	pub, err := x509.ParsePKIXPublicKey(pemBlock.Bytes)
	if err == nil {
		return pub.(*rsa.PublicKey), nil
	}

	pub, err = x509.ParsePKCS1PublicKey(pemBlock.Bytes)
	if err == nil {
		return pub.(*rsa.PublicKey), nil
	}

	// Another Public keys form parsing functions can be added here later
	// ...

	return nil, fmt.Errorf("ParseRsaPublicKeyFromPemFile(): unable to parse JWT public key: %w", err)
}

// ParseRsaPrivateKeyFromPemFile() loads rsa.PrivateKey from a PEM file
func ParseRsaPrivateKeyFromPemFile(privPEMLocation string) (*rsa.PrivateKey, error) {
	// Read a file content and convert it to a PEM block
	pemBlock, err := readFirstPEMBlockFromFile(privPEMLocation)
	if err != nil {
		return nil, fmt.Errorf("ParseRsaPrivateKeyFromPemFile(): %w", err)
	}

	if !strings.Contains(pemBlock.Type, "PRIVATE KEY") {
		return nil, errors.New("ParseRsaPrivateKeyFromPemFile(): provided file does not contain a PEM private key")
	}

	priv, err := x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
	if err == nil {
		return priv.(*rsa.PrivateKey), nil
	}

	priv, err = x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
	if err == nil {
		return priv.(*rsa.PrivateKey), nil
	}

	// Another Private keys form parsing functions can be added here later
	// ...

	return nil, fmt.Errorf("ParseRsaPrivateKeyFromPemFile(): unable to parse JWT private key: %w", err)
}

// ReadFirstPEMBlockFromFile() loads the first PEM block of a given PEM key file into a pem.Block structure
func readFirstPEMBlockFromFile(path string) (*pem.Block, error) {
	// Read the file content
	pubReadIn, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Decode the file content as a PEM block
	block, _ := pem.Decode(pubReadIn)
	if block == nil {
		return nil, fmt.Errorf("readFirstPEMBlockFromFile(): unable to decode a byte slice as a PEM block: %w", err)
	}

	return block, nil
}
