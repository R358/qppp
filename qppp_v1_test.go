package qppp

import (
	"testing"
)

const (
	LOOPBACK string = "127.0.0.1:10801"
)

func TestIPV4Decode(t *testing.T) {

	header := []byte("PROXY TCP4 192.168.0.1 192.168.0.11 56324 443\r\n")

	src, dest, err := parseHeader(NewTestConn(header))

	if err != nil {
		t.Error("Unexpected error:", err)
	}

	if src.String() != "192.168.0.1:56324" {
		t.Error("Incorrect src address: ", src.String())
	}
	if dest.String() != "192.168.0.11:443" {
		t.Error("Incorrect dst address: ", dest.String())
	}

}

func TestIPV6Decode(t *testing.T) {

	header := []byte("PROXY TCP6 2001:0db8:85a3:0000:0000:8a2e:0370:7334 1050:0:0:0:5:600:300c:326b 56324 443\r\n")

	src, dest, err := parseHeader(NewTestConn(header))

	if err != nil {
		t.Error("Unexpected error:", err)
	}

	if src.String() != "[2001:db8:85a3::8a2e:370:7334]:56324" {
		t.Error("Incorrect src address: ", src.String())
	}
	if dest.String() != "[1050::5:600:300c:326b]:443" {
		t.Error("Incorrect dst address: ", dest.String())
	}

}

func TestUnknownProtocolDecode(t *testing.T) {

	header := []byte("PROXY UNKNOWN 192.168.0.1 192.168.0.11 56324 443\r\n")

	src, dest, err := parseHeader(NewTestConn(header))

	if err != nil {
		t.Error("Unexpected error:", err)
	}

	if src != nil {
		t.Error("Incorrect src address: Should be nil")
	}
	if dest != nil {
		t.Error("Incorrect dst address: Should be nil")
	}

}

func TestNoUDPSupport(t *testing.T) {

	header := []byte("PROXY UDP4 192.168.0.1 192.168.0.11 56324 443\r\n")

	src, dest, err := parseHeader(NewTestConn(header))

	if err == nil {
		t.Error("Should get error.")
	}

	if err.Error() != "Unknown type: UDP4" {
		t.Error("Incorect error message: ", err.Error())
	}

	if src != nil {
		t.Error("Incorrect src address: Should be nil")
	}
	if dest != nil {
		t.Error("Incorrect dst address: Should be nil")
	}

}

func TestInvalidPort_SRC_Exceed(t *testing.T) {

	header := []byte("PROXY TCP4 192.168.0.1 192.168.0.11 80000 443\r\n")

	src, dest, err := parseHeader(NewTestConn(header))

	if err == nil {
		t.Error("Should get error.")
	}

	if err.Error() != "Port exceeds valid port number bounds 0 <= port <= 65535: 80000" {
		t.Error("Incorect error message: ", err.Error())
	}

	if src != nil {
		t.Error("Incorrect src address: Should be nil")
	}
	if dest != nil {
		t.Error("Incorrect dst address: Should be nil")
	}

}

func TestInvalidPort_SRC_Less(t *testing.T) {

	header := []byte("PROXY TCP4 192.168.0.1 192.168.0.11 -1 443\r\n")

	src, dest, err := parseHeader(NewTestConn(header))

	if err == nil {
		t.Error("Should get error.")
	}

	if err.Error() != "Port exceeds valid port number bounds 0 <= port <= 65535: -1" {
		t.Error("Incorect error message: ", err.Error())
	}

	if src != nil {
		t.Error("Incorrect src address: Should be nil")
	}
	if dest != nil {
		t.Error("Incorrect dst address: Should be nil")
	}

}

func TestInvalidPort_DST_Exceed(t *testing.T) {

	header := []byte("PROXY TCP4 192.168.0.1 192.168.0.11 1024 80000\r\n")

	src, dest, err := parseHeader(NewTestConn(header))

	if err == nil {
		t.Error("Should get error.")
	}

	if err.Error() != "Port exceeds valid port number bounds 0 <= port <= 65535: 80000" {
		t.Error("Incorect error message: ", err.Error())
	}

	if src != nil {
		t.Error("Incorrect src address: Should be nil")
	}
	if dest != nil {
		t.Error("Incorrect dst address: Should be nil")
	}

}

func TestInvalidPort_DST_Less(t *testing.T) {

	header := []byte("PROXY TCP4 192.168.0.1 192.168.0.11 1024 -1\r\n")

	src, dest, err := parseHeader(NewTestConn(header))

	if err == nil {
		t.Error("Should get error.")
	}

	if err.Error() != "Port exceeds valid port number bounds 0 <= port <= 65535: -1" {
		t.Error("Incorect error message: ", err.Error())
	}

	if src != nil {
		t.Error("Incorrect src address: Should be nil")
	}
	if dest != nil {
		t.Error("Incorrect dst address: Should be nil")
	}

}

func TestInvalid_SRCADDR(t *testing.T) {

	header := []byte("PROXY TCP4 392.168.0.1 192.168.0.11 1024 443\r\n")

	src, dest, err := parseHeader(NewTestConn(header))

	if err == nil {
		t.Error("Should get error.")
	}

	if err.Error() != "Invalid source ip: 392.168.0.1" {
		t.Error("Incorect error message: ", err.Error())
	}

	if src != nil {
		t.Error("Incorrect src address: Should be nil")
	}
	if dest != nil {
		t.Error("Incorrect dst address: Should be nil")
	}

}

func TestInvalid_DESTADDR(t *testing.T) {

	header := []byte("PROXY TCP4 192.168.0.1 392.168.0.11 1024 443\r\n")

	src, dest, err := parseHeader(NewTestConn(header))

	if err == nil {
		t.Error("Should get error.")
	}

	if err.Error() != "Invalid destination ip: 392.168.0.11" {
		t.Error("Incorect error message: ", err.Error())
	}

	if src != nil {
		t.Error("Incorrect src address: Should be nil")
	}
	if dest != nil {
		t.Error("Incorrect dst address: Should be nil")
	}

}

func TestInvalid_IPV6_SRCADDR(t *testing.T) {

	header := []byte("PROXY TCP6 r001:0db8:85a3:0000:0000:8a2e:0370:7334 1050:0:0:0:5:600:300c:326b 56324 443\r\n")

	src, dest, err := parseHeader(NewTestConn(header))

	if err == nil {
		t.Error("Should get error.")
	}

	if err.Error() != "Invalid source ip: r001:0db8:85a3:0000:0000:8a2e:0370:7334" {
		t.Error("Incorect error message: ", err.Error())
	}

	if src != nil {
		t.Error("Incorrect src address: Should be nil")
	}
	if dest != nil {
		t.Error("Incorrect dst address: Should be nil")
	}

}

func TestInvalid_IPV6_DSTADDR(t *testing.T) {

	header := []byte("PROXY TCP6 4001:0db8:85a3:0000:0000:8a2e:0370:7334 r050:0:0:0:5:600:300c:326b 56324 443\r\n")

	src, dest, err := parseHeader(NewTestConn(header))

	if err == nil {
		t.Error("Should get error.")
	}

	if err.Error() != "Invalid destination ip: r050:0:0:0:5:600:300c:326b" {
		t.Error("Incorect error message: ", err.Error())
	}

	if src != nil {
		t.Error("Incorrect src address: Should be nil")
	}
	if dest != nil {
		t.Error("Incorrect dst address: Should be nil")
	}

}

func TestInvalid_PROTOCOL(t *testing.T) {

	header := []byte("PROXY TCP7 192.168.0.1 192.168.0.11 56324 443\r\n")

	src, dest, err := parseHeader(NewTestConn(header))

	if err == nil {
		t.Error("Should get error.")
	}

	if err.Error() != "Unknown type: TCP7" {
		t.Error("Incorect error message: ", err.Error())
	}

	if src != nil {
		t.Error("Incorrect src address: Should be nil")
	}
	if dest != nil {
		t.Error("Incorrect dst address: Should be nil")
	}

}

func TestInvalid_MissingParams(t *testing.T) {

	header := []byte("PROXY TCP7 192.168.0.1 192.168.0.11 56324\r\n")

	src, dest, err := parseHeader(NewTestConn(header))

	if err == nil {
		t.Error("Should get error.")
	}

	if err.Error() != "Invalid header line: PROXY TCP7 192.168.0.1 192.168.0.11 56324" {
		t.Error("Incorect error message: ", err.Error())
	}

	if src != nil {
		t.Error("Incorrect src address: Should be nil")
	}
	if dest != nil {
		t.Error("Incorrect dst address: Should be nil")
	}

}

func TestInvalid_Command(t *testing.T) {

	header := []byte("PING TCP4 192.168.0.1 192.168.0.11 56324 443\r\n")

	src, dest, err := parseHeader(NewTestConn(header))

	if err == nil {
		t.Error("Should get error.")
	}

	if err.Error() != "Invalid header line: PING TCP4 192.168.0.1 192.168.0.11 56324 443" {
		t.Error("Incorect error message: ", err.Error())
	}

	if src != nil {
		t.Error("Incorrect src address: Should be nil")
	}
	if dest != nil {
		t.Error("Incorrect dst address: Should be nil")
	}

}

func TestInvalid_EndOfLine(t *testing.T) {

	header := []byte("PROXY TCP4 192.168.0.1 192.168.0.11 56324 443\nGET / HTTP/1.1\r\n")

	src, dest, err := parseHeader(NewTestConn(header))

	if err == nil {
		t.Error("Should get error.")
	}

	if err.Error() != "Invalid header line not terminated with \\r\\n: [Quoted Header] \"PROXY TCP4 192.168.0.1 192.168.0.11 56324 443\\n\"" {
		t.Error("Incorect error message: ", err.Error())
	}

	if src != nil {
		t.Error("Incorrect src address: Should be nil")
	}
	if dest != nil {
		t.Error("Incorrect dst address: Should be nil")
	}
}

func TestInvalid_TooLong(t *testing.T) {

	header := []byte("PROXY TCP4 192.168.0.1 192.168.0.11 56324 00000000000000000000000000000000000000000000000000000000000000000443\r\n")

	src, dest, err := parseHeader(NewTestConn(header))

	if err == nil {
		t.Error("Should get error.")
	}

	if err.Error() != "V1 Proxy header exceeds maximum size of 107 bytes. See 'http://www.haproxy.org/download/1.5/doc/proxy-protocol.txt'" {
		t.Error("Incorect error message: ", err.Error())
	}

	if src != nil {
		t.Error("Incorrect src address: Should be nil")
	}
	if dest != nil {
		t.Error("Incorrect dst address: Should be nil")
	}

}
