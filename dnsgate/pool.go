package dnsgate

import (
	"encoding/json"
	"fmt"
	"github.com/miekg/dns"
	"sync"
	"strings"
	"os"
)

const (
	ErrDnsConnectionTimeout = "dns_connection_timeout"
	ErrDnsWriteTimeout      = "dns_write_timeout"
	ErrDnsReadTimeout       = "dns_read_timeout"
	ErrDnsInternalError     = "dns_internal_error"
	ErrDnsWrongKeyPath = "dns_wrong_key_path"
)

type DnsError struct {
	Code  string
	Msg   string
	MsgId string
}

func (e *DnsError) Error() string {
	return fmt.Sprintf("Dns error:  code='%s'  msg = '%s', msg_id = '%s'", e.Code, e.Msg, e.MsgId)
}

func (e *DnsError) Json() []byte {
	j, _ := json.Marshal(map[string]string{
		"code":   e.Code,
		"msg":    e.Msg,
		"msg_id": e.Msg,
	})
	return j
}

func NewDnsError(msgId string, code string, msg string, a ...interface{}) *DnsError {
	return &DnsError{MsgId: msgId, Code: code, Msg: fmt.Sprintf(msg, a...)}
}

type DnsGate interface {
	AddSRV(srv []dns.RR) error
	Query(typ, key string) ([]dns.RR, error)
}

const poolLen uint32 = 16

const (
	ConnectionTimeoutSec uint32 = 30
	WriteTimeoutSec uint32 = 30
	ReadTimeoutSec uint32 = 30
)

type pooledUdpDnsGate struct {
	pool map[*udpGate]bool 
	poolGuard sync.RWMutex

	domain string
	port uint16
	key *dns.KEY
}

func newPooledUdpDnsGate(d string, p uint16, privkeyPath string) (DnsGate, error) {
	k, e := readDnsKey(privkeyPath)
	if e != nil {
		return nil, e
	}
	return &pooledUdpDnsGate{domain: d, port: p, key: k}, nil
}

func readDnsKey(privkeyPath string) (*dns.KEY, error) {
	if !strings.HasSuffix(privkeyPath, ".private") {
		return nil, NewDnsError("", ErrDnsWrongKeyPath, "Path: '%s'", privkeyPath)
	}

	var dir string
	var privkeyFile string
	if idx := strings.LastIndex(privkeyPath, "/"); idx == -1 {
		dir = ""
		privkeyFile = privkeyPath
	} else {
		dir = privkeyPath[:idx + 1]
		privkeyFile = privkeyPath[idx + 1:]
	}
	pubkeyFile := strings.TrimSuffix(privkeyFile, "private") + "key"

	pubf, e := os.Open(dir + pubkeyFile)
	if e != nil {
		return nil, NewDnsError("", ErrDnsWrongKeyPath, "Can not open public key file: '%s'", e.Error())
	}
	pubkey, e := dns.ReadRR(pubf, pubkeyFile)
	if e != nil {
		return nil, NewDnsError("", ErrDnsWrongKeyPath, "Can not parse public key: '%s'", e.Error())
	}

	privf, e := os.Open(privkeyPath)
	if e != nil {
		return nil, NewDnsError("", ErrDnsWrongKeyPath, "Can not open private key file: '%s'", e.Error())
	}
	key := pubkey.(*dns.KEY)
	_, e = key.ReadPrivateKey(privf, privkeyFile)
	if e != nil {
		return nil, NewDnsError("", ErrDnsWrongKeyPath, "Can not parse private key file: '%s'", e.Error())
	}
	return key, nil
}

func (p *pooledUdpDnsGate) AddSRV(srv []dns.RR) error {
	return nil
}

func (p *pooledUdpDnsGate) Query(typ, key string) ([]dns.RR, error) {
	return nil, nil
}
