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
	err     error
}

func NewUdpGate(address string, timeout time.Duration) (*udpGate, error) {
	attempt := 1
	for {
		if co, err := dns.DialTimeout("udp", address, timeout); err == nil {
			return &udpGate{conn: co, timeout: timeout}, nil
		} else {
			logger.Error("Attempt #%d to connect to '%s' DNS server failed: %s", attempt, address, err.Error())
			if err, ok := err.(net.Error); ok {
				switch {
				case err.Timeout():
					return nil, NewDnsError("", ErrDnsConnectionTimeout, err.Error())
				case err.Temporary() && attempt < 3:
					logger.Info("Detect temporary error. Try again.")
					time.Sleep(10 * time.Millisecond)
					attempt = attempt + 1
				default:
					return nil, NewDnsError("", ErrDnsConnectionError, err.Error())
				}
			} else {
				return nil, NewDnsError("", ErrDnsInternalError, err.Error())
			}
		}
	}
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
	ug.err = ug.conn.Close()
	return ug.err
}

func (ug *udpGate) SendMessageSync(msg []byte) ([]byte, error) {
	if ug.err = ug.setWriteDeadline(); ug.err != nil {
		logger.Error(ug.err.Error())
		return nil, ug.err
	}
	if _, ug.err = ug.write(msg); ug.err != nil {
		logger.Error(ug.err.Error())
		return nil, ug.err
	}

	if ug.err = ug.setReadDeadline(); ug.err != nil {
		logger.Error(ug.err.Error())
		return nil, ug.err
	}
	var r []byte
	if r, ug.err = ug.read(); ug.err != nil {
		logger.Error(ug.err.Error())
		return nil, ug.err
	}

	return r, nil
}
