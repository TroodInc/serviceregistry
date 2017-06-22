package dnsgate

import (
	"github.com/miekg/dns"
	"fmt"
	"encoding/json"
)


const (
	ErrDnsConnectioTimeout         = "dns_connection_timeout"
	ErrDnsWriteTimeout         = "dns_write_timeout"
	ErrDnsReadTimeout         = "dns_read_timeout"
	ErrDnsInternalError= "dns_internal_error"
)

type DnsError struct {
	Code        string
	Msg         string
	MsgId       string
}

func (e *DnsError) Error() string {
	return fmt.Sprintf("Dns error:  code='%s'  msg = '%s', msg_id = '%s'", e.Code, e.Msg, e.MsgId)
}

func (e *DnsError) Json() []byte {
	j, _ := json.Marshal(map[string]string{
		"code":        e.Code,
		"msg":         e.Msg,
		"msg_id":      e.Msg,
	})
	return j
}

func NewDnsError(msgId string, code string, msg string, a ...interface{}) *DnsError {
	return &DnsError{MsgId: msgId, Code: code, Msg: fmt.Sprintf(msg, a...)}
}

type DnsGate interface {
	AddSRV(srv *dns.RR) error
	Query(typ, key string) ([]dns.RR, error)
}

type pooledUdpDnsGate struct {
	pool map[*udpGate]bool 
}

