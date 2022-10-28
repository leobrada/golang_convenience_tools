package convenience_tools

import (
    "net"
    "encoding/base64"
    "fmt"
)

// TODO: needs better error handling
func ConvertAddrFromStringToIP(addr string) (net.IP, error) {
    addrBytes, err := base64.StdEncoding.DecodeString(addr)
    if err != nil {
        return nil, fmt.Errorf("convertAddrFromStringToIP: error decoding alert from flow exporter: %v", err)
    }

    addrIP := net.IP(addrBytes)

    return addrIP, nil
}
