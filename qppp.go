// qppp provides and implementation of proxy protocol Version 1 and Version 2.
// This implementation was original based on https://github.com/armon/go-proxyproto
// Which was then modified to implement the Version 2 proxy protocol.
// Test vectors were taken from Netty.io HAProxyMessageDecoderTest.java
// See https://github.com/netty/netty/blob/master/codec-haproxy/src/test/java/io/netty/handler/codec/haproxy/HAProxyMessageDecoderTest.java

package qppp

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	// prefix is the string we look for at the start of a connection
	// to check if this connection is using the proxy protocol
	prefix     = []byte("PROXY ")
	prefixLen  = len(prefix)
	v2Magic1   = []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D}
	v2Magic    = []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}
	v2MagicLen = len(v2Magic)
	v1Suffix   = "\r\n"
	errPrefix  = "ProxyProtocol: %s"
)

// Listener is used to wrap an underlying listener,
// whose connections may be using the HAProxy Proxy Protocol (version 1).
// If the connection is using the protocol, the RemoteAddr() will return
// the correct client address.
type Listener struct {
	Listener net.Listener
}

// Conn is used to wrap and underlying connection which
// may be speaking the Proxy Protocol. If it is, the RemoteAddr() will
// return the address of the client instead of the proxy address.
type Conn struct {
	bufReader *bufio.Reader
	conn      net.Conn
	dstAddr   *net.TCPAddr
	srcAddr   *net.TCPAddr
	once      sync.Once
}

// Accept waits for and returns the next connection to the listener.
func (p *Listener) Accept() (net.Conn, error) {
	// Get the underlying connection
	conn, err := p.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return NewConn(conn), nil
}

// Close closes the underlying listener.
func (p *Listener) Close() error {
	return p.Listener.Close()
}

// Addr returns the underlying listener's network address.
func (p *Listener) Addr() net.Addr {
	return p.Listener.Addr()
}

// NewConn is used to wrap a net.Conn that may be speaking
// the proxy protocol into a proxyproto.Conn
func NewConn(conn net.Conn) *Conn {
	pConn := &Conn{
		bufReader: bufio.NewReader(conn),
		conn:      conn,
	}
	return pConn
}

// Read is check for the proxy protocol header when doing
// the initial scan. If there is an error parsing the header,
// it is returned and the socket is closed.
func (p *Conn) Read(b []byte) (int, error) {
	var err error
	p.once.Do(func() { err = p.checkPrefix() })
	if err != nil {
		return 0, err
	}
	return p.bufReader.Read(b)
}

func (p *Conn) Write(b []byte) (int, error) {
	return p.conn.Write(b)
}

func (p *Conn) Close() error {
	return p.conn.Close()
}

func (p *Conn) LocalAddr() net.Addr {
	return p.conn.LocalAddr()
}

func (p *Conn) DestinationAddr() net.Addr {
	p.once.Do(func() {
		if err := p.checkPrefix(); err != nil && err != io.EOF {
			log.Printf("[ERR] Failed to read proxy prefix: %v", err)
		}
	})
	return p.dstAddr
}

func (p *Conn) SourceAddr() net.Addr {
	p.once.Do(func() {
		if err := p.checkPrefix(); err != nil && err != io.EOF {
			log.Printf("[ERR] Failed to read proxy prefix: %v", err)
		}
	})
	return p.srcAddr
}

// RemoteAddr returns the address of the client if the proxy
// protocol is being used, otherwise just returns the address of
// the socket peer. If there is an error parsing the header, the
// address of the client is not returned, and the socket is closed.
// Once implication of this is that the call could block if the
// client is slow. Using a Deadline is recommended if this is called
// before Read()
func (p *Conn) RemoteAddr() net.Addr {
	p.once.Do(func() {
		if err := p.checkPrefix(); err != nil && err != io.EOF {
			log.Printf("[ERR] Failed to read proxy prefix: %v", err)
		}
	})
	if p.srcAddr != nil {
		return p.srcAddr
	}
	return p.conn.RemoteAddr()
}

func (p *Conn) SetDeadline(t time.Time) error {
	return p.conn.SetDeadline(t)
}

func (p *Conn) SetReadDeadline(t time.Time) error {
	return p.conn.SetReadDeadline(t)
}

func (p *Conn) SetWriteDeadline(t time.Time) error {
	return p.conn.SetWriteDeadline(t)
}

func (p *Conn) checkPrefix() error {
	s, d, err := parseHeader(p.bufReader, p)
	p.srcAddr = s
	p.dstAddr = d
	return err
}

// parseHeader parses the initial data on the conn and attempts to decode a proxy protocol header.'
// It looks for (V1) "PROXY" or (V2)  0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D
// If neither or those are found then (nil,nil,nil) is returned.
// Returns: Source Address, Destination Address, error
// Decodes both V1 and V2 of Proxy protocol for IPV4 TCP, IPV6 TCP
// If the type is local or the address family is unknown then (nil,nil,nil) are returned.
// If the header cannot be fully decoded or values like ip address or port numbers are incorrect then
// an the error value of the return tuple is not null.
func parseHeader(bufReader *bufio.Reader, conn net.Conn) (*net.TCPAddr, *net.TCPAddr, error) {

	var dstAddr *net.TCPAddr = nil
	var srcAddr *net.TCPAddr = nil
	var err error = nil

	for i := 1; i <= prefixLen; i++ {
		inp, e := bufReader.Peek(i)
		if e != nil {
			dstAddr = nil
			srcAddr = nil
			return srcAddr, dstAddr, e
		}

		if bytes.Equal(inp, prefix[:i]) {
			srcAddr, dstAddr, err = parseV1(bufReader, conn)
			if err != nil {
				conn.Close()
			}

			if (srcAddr == nil || dstAddr == nil) && err != nil {
				conn.Close()
			}
			break
		} else if bytes.Equal(inp, v2Magic1[:i]) {
			srcAddr, dstAddr, err = parseV2(bufReader, conn)
			if err != nil {
				conn.Close()
			}

			if (srcAddr == nil || dstAddr == nil) && err != nil {
				conn.Close()
			}
			break
		} else {
			println("Not proxy protocol!!")
			return nil, nil, nil
		}
	}
	return srcAddr, dstAddr, err
}

func parseV2(bufReader *bufio.Reader, conn net.Conn) (*net.TCPAddr, *net.TCPAddr, error) {

	for i := 1; i <= v2MagicLen; i++ {
		inp, err := bufReader.Peek(i)
		if err != nil {
			return nil, nil, err
		}

		if !bytes.Equal(inp, v2Magic[:i]) {
			return nil, nil, nil
		}
	}

	// Burn off header... Oh for a Skip
	for i := v2MagicLen; i > 0; i-- {
		bufReader.ReadByte()
	}

	// Command byte
	cb, err := bufReader.ReadByte()

	if err != nil {
		return nil, nil, fmt.Errorf(errPrefix, err)
	}

	// Pass only LOCAL and PROXY [0x2][0 or 1]
	if cb != 0x20 && cb != 0x21 {
		return nil, nil, fmt.Errorf("Invalid command byte: Verion: %x, Instruction: %x", (cb&0xF0)>>4, (cb & 0x0F))
	}

	//
	// Deal with address family.
	//
	tpt, err := bufReader.ReadByte()
	if err != nil {
		return nil, nil, fmt.Errorf(errPrefix, err)
	}

	rb, err := readWord(bufReader)
	if err != nil {
		return nil, nil, fmt.Errorf(errPrefix, err)
	}

	switch tpt {

	case 0x00:

		// Skip remaining protocol bytes.
		for ; rb > 0; rb-- {
			bufReader.ReadByte()
		}

		return nil, nil, nil
		break

	case 0x11:
		if rb != 12 {
			return nil, nil, fmt.Errorf("Invalid protocol data length for IPV4 TCP %#04x must be %#04x", rb, 12)
		}

		// TCP IpV4
		b := make([]byte, 4)
		_, err = bufReader.Read(b)
		if err != nil {
			return nil, nil, fmt.Errorf(errPrefix, err)
		}

		srcIp := net.IP(b)

		b = make([]byte, 4)
		_, err = bufReader.Read(b)
		if err != nil {
			return nil, nil, fmt.Errorf(errPrefix, err)
		}

		destIp := net.IP(b)

		srcPort, err := readWord(bufReader)
		if err != nil {
			return nil, nil, fmt.Errorf(errPrefix, err)
		}

		destPort, err := readWord(bufReader)
		if err != nil {

			return nil, nil, fmt.Errorf(errPrefix, err)
		}

		srcAddr := &net.TCPAddr{IP: srcIp, Port: int(srcPort)}
		dstAddr := &net.TCPAddr{IP: destIp, Port: int(destPort)}

		return srcAddr, dstAddr, nil

	case 0x21:
		// TCP IpV6

		if rb != 36 {
			return nil, nil, fmt.Errorf("Invalid protocol data length for IPV4 TCP %#04x must be %#04x", rb, 36)
		}

		b := make([]byte, 16)
		_, err = bufReader.Read(b)
		if err != nil {

			return nil, nil, fmt.Errorf(errPrefix, err)
		}

		srcIp := net.IP(b)

		b = make([]byte, 16)
		_, err = bufReader.Read(b)
		if err != nil {

			return nil, nil, fmt.Errorf(errPrefix, err)
		}

		destIp := net.IP(b)

		srcPort, err := readWord(bufReader)
		if err != nil {

			return nil, nil, fmt.Errorf(errPrefix, err)
		}

		destPort, err := readWord(bufReader)
		if err != nil {

			return nil, nil, fmt.Errorf(errPrefix, err)
		}

		srcAddr := &net.TCPAddr{IP: srcIp, Port: int(srcPort)}
		dstAddr := &net.TCPAddr{IP: destIp, Port: int(destPort)}

		return srcAddr, dstAddr, nil

	case 0x12:
	case 0x22:
		return nil, nil, fmt.Errorf("Datagram transport protocol is not supported %x", tpt)

	default:
		return nil, nil, fmt.Errorf("Unknown transport protocol: %x", tpt)

	}

	return nil, nil, nil
}

func readWord(bufReader *bufio.Reader) (uint, error) {
	msb, err := bufReader.ReadByte()
	if err != nil {
		return 0, fmt.Errorf(errPrefix, err)
	}

	lsb, err := bufReader.ReadByte()
	if err != nil {
		return 0, fmt.Errorf(errPrefix, err)
	}

	return (uint(msb) << 8) | uint(lsb), nil

}

func parseV1(bufReader *bufio.Reader, conn net.Conn) (*net.TCPAddr, *net.TCPAddr, error) {
	// Read the header line
	header, err := bufReader.ReadString('\n')
	if err != nil {
		return nil, nil, fmt.Errorf(errPrefix, err)
	}

	if len(header) > 107 {
		return nil, nil, fmt.Errorf("V1 Proxy header exceeds maximum size of 107 bytes. See 'http://www.haproxy.org/download/1.5/doc/proxy-protocol.txt'")
	}

	if !strings.HasSuffix(header, v1Suffix) {
		return nil, nil, fmt.Errorf("Invalid header line not terminated with \\r\\n: [Quoted Header] %s", strconv.Quote(header))
	}

	// Strip the carriage return and new line
	header = header[:len(header)-2]

	// Split on spaces, should be (PROXY <type> <src addr> <dst addr> <src port> <dst port>)
	parts := strings.Split(header, " ")
	if len(parts) != 6 || parts[0] != "PROXY" {
		return nil, nil, fmt.Errorf("Invalid header line: %s", header)
	}

	// Verify the type is known
	switch parts[1] {
	case "TCP4":
	case "TCP6":
	case "UNKNOWN":
		return nil, nil, nil
	default:
		return nil, nil, errors.New("Unknown type: " + parts[1])
	}

	// Parse out the source address
	ip := net.ParseIP(parts[2])
	if ip == nil {

		return nil, nil, fmt.Errorf("Invalid source ip: %s", parts[2])
	}
	port, err := strconv.Atoi(parts[4])
	if err != nil {
		return nil, nil, fmt.Errorf("Invalid source port: %s", parts[4])
	}

	if port < 0 || port > 65535 {
		return nil, nil, fmt.Errorf("Port exceeds valid port number bounds 0 <= port <= 65535: %s", parts[4])
	}

	srcAddr := &net.TCPAddr{IP: ip, Port: port}

	// Parse out the destination address
	ip = net.ParseIP(parts[3])
	if ip == nil {
		return nil, nil, fmt.Errorf("Invalid destination ip: %s", parts[3])
	}
	port, err = strconv.Atoi(parts[5])
	if err != nil {
		return nil, nil, fmt.Errorf("Invalid destination port: %s", parts[5])
	}

	if port < 0 || port > 65535 {
		return nil, nil, fmt.Errorf("Port exceeds valid port number bounds 0 <= port <= 65535: %s", parts[5])
	}

	dstAddr := &net.TCPAddr{IP: ip, Port: port}

	return srcAddr, dstAddr, nil
}
