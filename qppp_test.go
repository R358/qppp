package qppp

import (
	"bufio"
	"bytes"
	"net"
	"time"
)

// Verify that testConn actually implements net.Conn
var _ net.Conn = &testConn{}

// testConn is a test local implementation of net.Conn for testing purposes only.
type testConn struct {
	localAddr  net.TCPAddr
	remoteAddr net.TCPAddr
	buf        *bytes.Buffer
}

func (c testConn) Read(b []byte) (n int, err error) {
	return c.buf.Read(b)
}

func (c testConn) Write(b []byte) (n int, err error) {
	return c.buf.Write(b)
}

func (c testConn) Close() error {
	return nil
}

func (c testConn) LocalAddr() net.Addr {
	return &(c.localAddr)
}

func (c testConn) RemoteAddr() net.Addr {
	return &(c.remoteAddr)
}

func (c testConn) SetDeadline(t time.Time) error {
	return nil
}

func (c testConn) SetReadDeadline(t time.Time) error { return nil }

func (c testConn) SetWriteDeadline(t time.Time) error {
	return nil
}

// acceptPw performs the same accept operation except it returns qppp.Conn and is used fo testing only.
func (p *Listener) acceptPw() (*Conn, error) {
	// Get the underlying connection
	conn, err := p.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return NewConn(conn), nil
}

func NewTestConn(data []byte) (*bufio.Reader, net.Conn) {
	conn := testConn{
		buf: bytes.NewBuffer(data)}

	return bufio.NewReader(conn), conn
}
