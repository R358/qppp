package qppp

import (
	"testing"
)

func TestV2IPV4Decode(t *testing.T) {

	header := make([]byte, 28)
	header[0] = 0x0D  // Binary Prefix
	header[1] = 0x0A  // -----
	header[2] = 0x0D  // -----
	header[3] = 0x0A  // -----
	header[4] = 0x00  // -----
	header[5] = 0x0D  // -----
	header[6] = 0x0A  // -----
	header[7] = 0x51  // -----
	header[8] = 0x55  // -----
	header[9] = 0x49  // -----
	header[10] = 0x54 // -----
	header[11] = 0x0A // -----

	header[12] = 0x21 // v2, cmd=PROXY
	header[13] = 0x11 // TCP over IPv4

	header[14] = 0x00 // Remaining Bytes
	header[15] = 0x0c // -----

	header[16] = 0xc0 // Source Address
	header[17] = 0xa8 // -----
	header[18] = 0x00 // -----
	header[19] = 0x01 // -----

	header[20] = byte(0xc0) // Destination Address
	header[21] = byte(0xa8) // -----
	header[22] = 0x00       // -----
	header[23] = 0x0b       // -----

	header[24] = 0xdc // Source Port
	header[25] = 0x04 // -----

	header[26] = 0x01       // Destination Port
	header[27] = byte(0xbb) // -----

	src, dest, err := parseHeader(NewTestConn(header))

	if err != nil {
		t.Error("Unexpected error:", err)
	}

	if src.String() != "192.168.0.1:56324" {
		t.Errorf("Incorrect source address: %s", src.String())
	}

	if dest.String() != "192.168.0.11:443" {
		t.Errorf("Incorrect dest address: %s", dest.String())
	}
}

func TestV2IPV6Decode(t *testing.T) {
	header := make([]byte, 52)

	header[0] = 0x0D  // Binary Prefix
	header[1] = 0x0A  // -----
	header[2] = 0x0D  // -----
	header[3] = 0x0A  // -----
	header[4] = 0x00  // -----
	header[5] = 0x0D  // -----
	header[6] = 0x0A  // -----
	header[7] = 0x51  // -----
	header[8] = 0x55  // -----
	header[9] = 0x49  // -----
	header[10] = 0x54 // -----
	header[11] = 0x0A // -----

	header[12] = 0x21 // v2, cmd=PROXY
	header[13] = 0x21 // TCP over IPv6

	header[14] = 0x00 // Remaining Bytes
	header[15] = 0x24 // -----

	header[16] = 0x20 // Source Address
	header[17] = 0x01 // -----
	header[18] = 0x0d // -----
	header[19] = 0xb8 // -----
	header[20] = 0x85 // -----
	header[21] = 0xa3 // -----
	header[22] = 0x00 // -----
	header[23] = 0x00 // -----
	header[24] = 0x00 // -----
	header[25] = 0x00 // -----
	header[26] = 0x8a // -----
	header[27] = 0x2e // -----
	header[28] = 0x03 // -----
	header[29] = 0x70 // -----
	header[30] = 0x73 // -----
	header[31] = 0x34 // -----

	header[32] = 0x10 // Destination Address
	header[33] = 0x50 // -----
	header[34] = 0x00 // -----
	header[35] = 0x00 // -----
	header[36] = 0x00 // -----
	header[37] = 0x00 // -----
	header[38] = 0x00 // -----
	header[39] = 0x00 // -----
	header[40] = 0x00 // -----
	header[41] = 0x05 // -----
	header[42] = 0x06 // -----
	header[43] = 0x00 // -----
	header[44] = 0x30 // -----
	header[45] = 0x0c // -----
	header[46] = 0x32 // -----
	header[47] = 0x6b // -----

	header[48] = 0xdc // Source Port
	header[49] = 0x04 // -----

	header[50] = 0x01 // Destination Port
	header[51] = 0xbb // -----

	src, dest, err := parseHeader(NewTestConn(header))

	if err != nil {
		t.Error("Unexpected error:", err)
	}

	if src.String() != "[2001:db8:85a3::8a2e:370:7334]:56324" {
		t.Errorf("Incorrect source address: %s", src.String())
	}

	if dest.String() != "[1050::5:600:300c:326b]:443" {
		t.Errorf("Incorrect dest address: %s", dest.String())
	}

}

func TestV2Local(t *testing.T) {
	header := make([]byte, 52)

	header[0] = 0x0D  // Binary Prefix
	header[1] = 0x0A  // -----
	header[2] = 0x0D  // -----
	header[3] = 0x0A  // -----
	header[4] = 0x00  // -----
	header[5] = 0x0D  // -----
	header[6] = 0x0A  // -----
	header[7] = 0x51  // -----
	header[8] = 0x55  // -----
	header[9] = 0x49  // -----
	header[10] = 0x54 // -----
	header[11] = 0x0A // -----

	header[12] = 0x20 // v2, cmd=LOCAL
	header[13] = 0x00 // Unspecified transport protocol and address family

	header[14] = 0x00 // Remaining Bytes
	header[15] = 0x0c // -----

	header[16] = 0xc0 // Source Address
	header[17] = 0xa8 // -----
	header[18] = 0x00 // -----
	header[19] = 0x01 // -----

	header[20] = 0xc0 // Destination Address
	header[21] = 0xa8 // -----
	header[22] = 0x00 // -----
	header[23] = 0x0b // -----

	header[24] = 0xdc // Source Port
	header[25] = 0x04 // -----

	header[26] = 0x01 // Destination Port
	header[27] = 0xbb // -----

	src, dest, err := parseHeader(NewTestConn(header))

	if err != nil {
		t.Error("Unexpected error:", err)
	}

	if src != nil {
		t.Error("Src address must be null.")
	}

	if dest != nil {
		t.Errorf("Dest address must be null.")
	}

}

func TestV2UnknownProtocol(t *testing.T) {
	header := make([]byte, 52)

	header[0] = 0x0D  // Binary Prefix
	header[1] = 0x0A  // -----
	header[2] = 0x0D  // -----
	header[3] = 0x0A  // -----
	header[4] = 0x00  // -----
	header[5] = 0x0D  // -----
	header[6] = 0x0A  // -----
	header[7] = 0x51  // -----
	header[8] = 0x55  // -----
	header[9] = 0x49  // -----
	header[10] = 0x54 // -----
	header[11] = 0x0A // -----

	header[12] = 0x21 // v2, cmd=PROXY
	header[13] = 0x00 // Unspecified transport protocol and address family

	header[14] = 0x00 // Remaining Bytes
	header[15] = 0x0c // -----

	header[16] = 0xc0 // Source Address
	header[17] = 0xa8 // -----
	header[18] = 0x00 // -----
	header[19] = 0x01 // -----

	header[20] = 0xc0 // Destination Address
	header[21] = 0xa8 // -----
	header[22] = 0x00 // -----
	header[23] = 0x0b // -----

	header[24] = 0xdc // Source Port
	header[25] = 0x04 // -----

	header[26] = 0x01 // Destination Port
	header[27] = 0xbb // -----

	src, dest, err := parseHeader(NewTestConn(header))

	if err != nil {
		t.Error("Unexpected error:", err)
	}

	if src != nil {
		t.Error("Src address must be null.")
	}

	if dest != nil {
		t.Errorf("Dest address must be null.")
	}

}

func TestV2InvalidProtocol(t *testing.T) {
	header := make([]byte, 52)

	header[0] = 0x0D  // Binary Prefix
	header[1] = 0x0A  // -----
	header[2] = 0x0D  // -----
	header[3] = 0x0A  // -----
	header[4] = 0x00  // -----
	header[5] = 0x0D  // -----
	header[6] = 0x0A  // -----
	header[7] = 0x51  // -----
	header[8] = 0x55  // -----
	header[9] = 0x49  // -----
	header[10] = 0x54 // -----
	header[11] = 0x0A // -----

	header[12] = 0x21 // v2, cmd=PROXY
	header[13] = 0x41 // Bogus transport protocol

	header[14] = 0x00 // Remaining Bytes
	header[15] = 0x0c // -----

	header[16] = 0xc0 // Source Address
	header[17] = 0xa8 // -----
	header[18] = 0x00 // -----
	header[19] = 0x01 // -----

	header[20] = 0xc0 // Destination Address
	header[21] = 0xa8 // -----
	header[22] = 0x00 // -----
	header[23] = 0x0b // -----

	header[24] = 0xdc // Source Port
	header[25] = 0x04 // -----

	header[26] = 0x01 // Destination Port
	header[27] = 0xbb // -----

	_, _, err := parseHeader(NewTestConn(header))

	if err == nil {
		t.Fatal("Must get error..!")
	}

	if err.Error() != "Unknown transport protocol: 41" {
		t.Fatal("Incorrect error message got:", err.Error())
	}

}

func TestV2MissingData(t *testing.T) {
	header := make([]byte, 52)

	header[0] = 0x0D  // Binary Prefix
	header[1] = 0x0A  // -----
	header[2] = 0x0D  // -----
	header[3] = 0x0A  // -----
	header[4] = 0x00  // -----
	header[5] = 0x0D  // -----
	header[6] = 0x0A  // -----
	header[7] = 0x51  // -----
	header[8] = 0x55  // -----
	header[9] = 0x49  // -----
	header[10] = 0x54 // -----
	header[11] = 0x0A // -----

	header[12] = 0x21 // v2, cmd=PROXY
	header[13] = 0x11 // TCP over IPv4

	header[14] = 0x00 // Remaining Bytes
	header[15] = 0x0a // -----

	header[16] = 0xc0 // Source Address
	header[17] = 0xa8 // -----
	header[18] = 0x00 // -----
	header[19] = 0x01 // -----

	header[20] = 0xc0 // Destination Address
	header[21] = 0xa8 // -----
	header[22] = 0x00 // -----
	header[23] = 0x0b // -----

	header[24] = 0xdc // Source Port
	header[25] = 0x04 // -----

	_, _, err := parseHeader(NewTestConn(header))

	if err == nil {
		t.Fatal("Must get error..!")
	}

	if err.Error() != "Invalid protocol data length for IPV4 TCP 0x000a must be 0x000c" {
		t.Fatal("Incorrect error message got:", err.Error())
	}

}

func TestV2InvalidCommand(t *testing.T) {
	header := make([]byte, 52)

	header[0] = 0x0D  // Binary Prefix
	header[1] = 0x0A  // -----
	header[2] = 0x0D  // -----
	header[3] = 0x0A  // -----
	header[4] = 0x00  // -----
	header[5] = 0x0D  // -----
	header[6] = 0x0A  // -----
	header[7] = 0x51  // -----
	header[8] = 0x55  // -----
	header[9] = 0x49  // -----
	header[10] = 0x54 // -----
	header[11] = 0x0A // -----

	header[12] = 0x22 // v2, Bogus command
	header[13] = 0x11 // TCP over IPv4

	header[14] = 0x00 // Remaining Bytes
	header[15] = 0x0c // -----

	header[16] = 0xc0 // Source Address
	header[17] = 0xa8 // -----
	header[18] = 0x00 // -----
	header[19] = 0x01 // -----

	header[20] = 0xc0 // Destination Address
	header[21] = 0xa8 // -----
	header[22] = 0x00 // -----
	header[23] = 0x0b // -----

	header[24] = 0xdc // Source Port
	header[25] = 0x04 // -----

	header[26] = 0x01 // Destination Port
	header[27] = 0xbb // -----

	_, _, err := parseHeader(NewTestConn(header))

	if err == nil {
		t.Fatal("Must get error..!")
	}

	if err.Error() != "Invalid command byte: Verion: 2, Instruction: 2" {
		t.Fatal("Incorrect error message got:", err.Error())
	}

}

func TestV2InvalidVersion(t *testing.T) {
	header := make([]byte, 52)

	header[0] = 0x0D  // Binary Prefix
	header[1] = 0x0A  // -----
	header[2] = 0x0D  // -----
	header[3] = 0x0A  // -----
	header[4] = 0x00  // -----
	header[5] = 0x0D  // -----
	header[6] = 0x0A  // -----
	header[7] = 0x51  // -----
	header[8] = 0x55  // -----
	header[9] = 0x49  // -----
	header[10] = 0x54 // -----
	header[11] = 0x0A // -----

	header[12] = 0x31 // Bogus version, cmd=PROXY
	header[13] = 0x11 // TCP over IPv4

	header[14] = 0x00 // Remaining Bytes
	header[15] = 0x0c // -----

	header[16] = 0xc0 // Source Address
	header[17] = 0xa8 // -----
	header[18] = 0x00 // -----
	header[19] = 0x01 // -----

	header[20] = 0xc0 // Destination Address
	header[21] = 0xa8 // -----
	header[22] = 0x00 // -----
	header[23] = 0x0b // -----

	header[24] = 0xdc // Source Port
	header[25] = 0x04 // -----

	header[26] = 0x01 // Destination Port
	header[27] = 0xbb // -----

	_, _, err := parseHeader(NewTestConn(header))

	if err == nil {
		t.Fatal("Must get error..!")
	}

	if err.Error() != "Invalid command byte: Verion: 3, Instruction: 1" {
		t.Fatal("Incorrect error message got:", err.Error())
	}

}

func TestV2HeaderTooLong(t *testing.T) {
	header := make([]byte, 248)

	header[0] = 0x0D  // Binary Prefix
	header[1] = 0x0A  // -----
	header[2] = 0x0D  // -----
	header[3] = 0x0A  // -----
	header[4] = 0x00  // -----
	header[5] = 0x0D  // -----
	header[6] = 0x0A  // -----
	header[7] = 0x51  // -----
	header[8] = 0x55  // -----
	header[9] = 0x49  // -----
	header[10] = 0x54 // -----
	header[11] = 0x0A // -----

	header[12] = 0x21 // v2, cmd=PROXY
	header[13] = 0x11 // TCP over IPv4

	header[14] = 0x00 // Remaining Bytes
	header[15] = 0xe8 // -----

	header[16] = 0xc0 // Source Address
	header[17] = 0xa8 // -----
	header[18] = 0x00 // -----
	header[19] = 0x01 // -----

	header[20] = 0xc0 // Destination Address
	header[21] = 0xa8 // -----
	header[22] = 0x00 // -----
	header[23] = 0x0b // -----

	header[24] = 0xdc // Source Port
	header[25] = 0x04 // -----

	header[26] = 0x01 // Destination Port
	header[27] = 0xbb // -----

	_, _, err := parseHeader(NewTestConn(header))

	if err == nil {
		t.Fatal("Must get error..!")
	}

	if err.Error() != "Invalid protocol data length for IPV4 TCP 0x00e8 must be 0x000c" {
		t.Fatal("Incorrect error message got:", err.Error())
	}

}

func TestV2IncompleteHeader(t *testing.T) {
	header := make([]byte, 13)
	header[0] = 0x0D  // Binary Prefix
	header[1] = 0x0A  // -----
	header[2] = 0x0D  // -----
	header[3] = 0x0A  // -----
	header[4] = 0x00  // -----
	header[5] = 0x0D  // -----
	header[6] = 0x0A  // -----
	header[7] = 0x51  // -----
	header[8] = 0x55  // -----
	header[9] = 0x49  // -----
	header[10] = 0x54 // -----
	header[11] = 0x0A // -----

	header[12] = 0x21 // v2, cmd=PROXY

	_, _, err := parseHeader(NewTestConn(header))

	if err == nil {
		t.Fatal("Must get error..!")
	}

	if err.Error() != "ProxyProtocol: EOF" {
		t.Fatal("Incorrect error message got:", err.Error())
	}

}
