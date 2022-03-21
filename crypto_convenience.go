package convenience_tools

import (
    "fmt"
    "crypto/tls"
    "crypto/x509"
    "io/ioutil"
)

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
