package convenience_tools

import (
    "crypto/tls"
    "net/http"
)


func NewHTTPSClient(caCertPoolClientAccepts *x509.CertPoo, certShownByClient tls.Certificate) *http.Client {

    client := new(http.Client)
    client.Transport = &http.Transport{
        TLSClientConfig: &tls.Config{
            Certificates:       []tls.Certificate{certShownByClient},
            InsecureSkipVerify: true,
            ClientAuth:         tls.RequireAndVerifyClientCert,
            ClientCAs:          caCertPoolClientAccepts,
        },
    }

    return client
}

func NewHTTPSClientPool(poolSize int, caCertPoolClientAccepts *x509.CertPoo, certShownByClient tls.Certificate) []*http.Client {
    clientPool := make([]*http.Client, poolSize)

    for i := 0; i < poolSize; i++ {
        client := new(http.Client)
            client.Transport = &http.Transport{
                TLSClientConfig: &tls.Config{
                    Certificates:       []tls.Certificate{certShownByClient},
                    InsecureSkipVerify: true,
                    ClientAuth:         tls.RequireAndVerifyClientCert,
                    ClientCAs:          caCertPoolClientAccepts,
            },
        }
        clientPool[i] = client
    }

    return clientPool
}
