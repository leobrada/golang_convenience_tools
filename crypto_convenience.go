package convenience_tools

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
)

// X509 PART
// Deprecated: function unifies the loading of CA certificates
func LoadCACertificate(certfile string, certPool *x509.CertPool) error {
	caRoot, err := os.ReadFile(certfile)
	if err != nil {
		return fmt.Errorf("loadCACertificate(): Loading CA certificate from %s error: %v", certfile, err)
	}

	certPool.AppendCertsFromPEM(caRoot)
	return nil
}

// function unifies the loading of CA certificates and appends them to CertPool and to a slice
func LoadCertificate(certfile string, certPool *x509.CertPool, certSlice []*x509.Certificate) ([]*x509.Certificate, error) {
	certPEM, err := os.ReadFile(certfile)
	if err != nil {
		return nil, fmt.Errorf("LoadCertificate(): Loading CA certificate from %s error: %v", certfile, err)
	}

	if certPool != nil {
		certPool.AppendCertsFromPEM(certPEM)
	}

	if certSlice != nil {
		certDER, _ := pem.Decode(certPEM)
		if (certDER == nil) || (certDER.Type != "CERTIFICATE") {
			return nil, fmt.Errorf("LoadCertificate(): Could not append certificate to certificate slice error: %v", err)
		}

		cert, err := x509.ParseCertificate(certDER.Bytes)
		if err != nil {
			return nil, fmt.Errorf("LoadCertificate(): Could not append certificate to certificate slice error: %v", err)
		}

		certSlice = append(certSlice, cert)
	}

	return certSlice, nil
}

// function unifies the loading of X509 key pairs
func LoadX509KeyPair(certfile, keyfile string) (tls.Certificate, error) {
	keyPair, err := tls.LoadX509KeyPair(certfile, keyfile)
	if err != nil {
		return keyPair, fmt.Errorf("loadX509KeyPair(): critical error when loading X509KeyPair from %s and %s: %v", certfile, keyfile, err)
	}

	return keyPair, nil
}

func GetIssuerDNInDER(cert tls.Certificate) ([]byte, error) {
	if len(cert.Certificate) == 0 {
		return nil, fmt.Errorf("GetIssuerDNInDER(): provided certificate is empty")
	}

	// Parse the leaf certificate, assuming cert.Certificate[0] is the leaf
	leafCert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, err
	}

	// Get the issuer's Distinguished Name as an RDNSequence
	rdnSequence := leafCert.Issuer.ToRDNSequence()

	// Marshal the RDNSequence back to DER
	derBytes, err := asn1.Marshal(rdnSequence)
	if err != nil {
		return nil, err
	}

	return derBytes, nil
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
	pubReadIn, err := os.ReadFile(path)
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
