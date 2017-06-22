package dnsgate

import (
	"git.reaxoft.loc/infomir/director/logger"
	"github.com/miekg/dns"
	"net"
	"time"
)

type udpGate struct {
	conn    *dns.Conn
	timeout time.Duration
}

//
func NewUdpGate(address string, timeout time.Duration) (*udpGate, error) {
	co, err := dns.DialTimeout("udp", address, timeout)
	if err, ok := err.(net.Error); ok {
		logger.Error(err.Error())
		var code string
		if err.Timeout() {
			code = ErrDnsConnectionTimeout
		} else {
			code = ErrDnsConnectionError
		}
		return nil, NewDnsError("", code, err.Error())
	} else if err != nil {
		logger.Error(err.Error())
		return nil, NewDnsError("", ErrDnsInternalError, err.Error())
	}

	return &udpGate{co, timeout}, nil
}

func (ug *udpGate) deadline() time.Time {
	return time.Now().Add(ug.timeout)
}

func (ug *udpGate) setWriteDeadline() error {
	if err := ug.conn.SetWriteDeadline(ug.deadline()); err != nil {
		return NewDnsError("", ErrDnsInternalError, err.Error())
	}
	return nil
}

func (ug *udpGate) setReadDeadline() error {
	if err := ug.conn.SetReadDeadline(ug.deadline()); err != nil {
		return NewDnsError("", ErrDnsInternalError, err.Error())
	}
	return nil
}

func (ug *udpGate) write(msg []byte) (int, error) {
	n, err := ug.conn.Write(msg)
	if err, ok := err.(net.Error); ok && err.Timeout() {
		return n, NewDnsError("", ErrDnsWriteTimeout, err.Error())
	} else if err != nil {
		return n, NewDnsError("", ErrDnsInternalError, err.Error())
	}
	return n, nil
}

func (ug *udpGate) read() ([]byte, error) {
	r, err := ug.conn.ReadMsgHeader(nil)
	if err, ok := err.(net.Error); ok && err.Timeout() {
		return nil, NewDnsError("", ErrDnsReadTimeout, err.Error())
	} else if err != nil {
		return nil, NewDnsError("", ErrDnsInternalError, err.Error())
	}
	return r, nil
}

func (ug *udpGate) Release() error {
	return ug.conn.Close()
}

func (ug *udpGate) SendMessageSync(msg []byte) ([]byte, error) {
	if err := ug.setWriteDeadline(); err != nil {
		logger.Error(err.Error())
		return nil, err
	}
	if _, err := ug.write(msg); err != nil {
		logger.Error(err.Error())
		return nil, err
	}

	if err := ug.setReadDeadline(); err != nil {
		logger.Error(err.Error())
		return nil, err
	}
	r, err := ug.read()
	if err != nil {
		logger.Error(err.Error())
		return nil, err
	}

	return r, nil
}
