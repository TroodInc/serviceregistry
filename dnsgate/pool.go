package dnsgate

import (
	"encoding/json"
	"fmt"
	"github.com/miekg/dns"
	"os"
	"strings"
	"sync/atomic"
	"strconv"
	"time"
	"crypto"
	"crypto/rsa"
)

const (
	ErrDnsConnectionError   = "dns_connection_error"
	ErrDnsConnectionTimeout = "dns_connection_timeout"
	ErrDnsWriteTimeout      = "dns_write_timeout"
	ErrDnsReadTimeout       = "dns_read_timeout"
	ErrDnsInternalError     = "dns_internal_error"
	ErrDnsWrongKeyPath      = "dns_wrong_key_path"
	ErrDnsSigningError      = "dns_signing_error"
	ErrDnsBadResponseMessage      = "dns_bad_response_message"
	ErrDnsUpdateFailed      = "dns_update_failed"
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
	AddSRV(zone string, srv []dns.RR) error
	Query(typ, key string) ([]dns.RR, error)
}

const poolMaxSize uint32 = 16

const (
	ConnectionTimeoutSec time.Duration = 30 * time.Second
	WriteTimeoutSec      = 30 * time.Second
	ReadTimeoutSec       = 30 * time.Second
)

type pooledUdpDnsGate struct {
	pool     chan *udpGate
	poolSize uint32

	domain string
	port   uint16
	key    *dns.KEY
	privkey crypto.PrivateKey
}

func newPooledUdpDnsGate(d string, p uint16, privkeyPath string) (DnsGate, error) {
	k, pk, e := readDnsKey(privkeyPath)
	if e != nil {
		return nil, e
	}
	return &pooledUdpDnsGate{domain: d, port: p, key: k, privkey: pk, pool: make(chan *udpGate, poolMaxSize)}, nil
}

func readDnsKey(privkeyPath string) (*dns.KEY, crypto.PrivateKey, error) {
	if !strings.HasSuffix(privkeyPath, ".private") {
		return nil, nil, NewDnsError("", ErrDnsWrongKeyPath, "Path: '%s'", privkeyPath)
	}

	var dir string
	var privkeyFile string
	if idx := strings.LastIndex(privkeyPath, "/"); idx == -1 {
		dir = ""
		privkeyFile = privkeyPath
	} else {
		dir = privkeyPath[:idx+1]
		privkeyFile = privkeyPath[idx+1:]
	}
	pubkeyFile := strings.TrimSuffix(privkeyFile, "private") + "key"

	pubf, e := os.Open(dir + pubkeyFile)
	if e != nil {
		return nil, nil, NewDnsError("", ErrDnsWrongKeyPath, "Can not open public key file: '%s'", e.Error())
	}
	pubkey, e := dns.ReadRR(pubf, pubkeyFile)
	if e != nil {
		return nil, nil, NewDnsError("", ErrDnsWrongKeyPath, "Can not parse public key: '%s'", e.Error())
	}

	privf, e := os.Open(privkeyPath)
	if e != nil {
		return nil, nil, NewDnsError("", ErrDnsWrongKeyPath, "Can not open private key file: '%s'", e.Error())
	}
	key := pubkey.(*dns.KEY)
	privkey, e := key.ReadPrivateKey(privf, privkeyFile)
	if e != nil {
		return nil, nil, NewDnsError("", ErrDnsWrongKeyPath, "Can not parse private key file: '%s'", e.Error())
	}
	return key, privkey, nil
}

func (p *pooledUdpDnsGate) acquire() (g *udpGate, err error) {
	select {
	case con := <-p.pool:
		return con, nil
	default: 
		if atomic.LoadUint32(&p.poolSize) >= poolMaxSize {
			con := <-p.pool
			return con, nil
		} else {
			if atomic.AddUint32(&p.poolSize, 1) > poolMaxSize {
				atomic.AddUint32(&p.poolSize, ^uint32(0))
				con := <-p.pool
				return con, nil
			} else {
				defer func() {
					if r := recover(); r != nil {
						atomic.AddUint32(&p.poolSize, ^uint32(0))
						err = NewDnsError("", ErrDnsConnectionError, "Error while connection: %v", r)
						g = nil
					}
				}()
				con, e := NewUdpGate(p.domain + ":" + strconv.FormatUint(uint64(p.port), 10), ConnectionTimeoutSec)
				if e != nil {
					atomic.AddUint32(&p.poolSize, ^uint32(0))
					return nil, e
				}
				return con, nil
			}
		}
	}
	return nil, nil
}

func (p *pooledUdpDnsGate) release(g *udpGate) {
	if g.err != nil {
		atomic.AddUint32(&p.poolSize, ^uint32(0))
		g.Release()
	} else {
		select {
		case p.pool<- g:
			return
		default:
			atomic.AddUint32(&p.poolSize, ^uint32(0))
			g.Release()
		}
	}
}

func (p *pooledUdpDnsGate) AddSRV(zone string, srv []dns.RR) error {
	m := new(dns.Msg)
	m.SetUpdate(zone)
	m.Insert(srv)

	now := uint32(time.Now().Unix())
	sig := new(dns.SIG)
	sig.Hdr.Name = "."
	sig.Hdr.Rrtype = dns.TypeSIG
	sig.Hdr.Class = dns.ClassANY
	sig.Algorithm = p.key.Algorithm
	sig.SignerName = p.key.Hdr.Name
	sig.Expiration = now + 300
	sig.Inception = now - 300
	sig.KeyTag = p.key.KeyTag()

	mb, e := sig.Sign(p.privkey.(*rsa.PrivateKey), m)
	if e != nil {
		return NewDnsError(strconv.FormatUint(uint64(m.Id), 10), ErrDnsSigningError, "Signing error: %s", e.Error())
	}

	g, e := p.acquire()
	if e != nil {
		return e
	}
	defer p.release(g)

	rb, e := g.SendMessageSync(mb)
	if e != nil {
		return nil
	}

	r := new(dns.Msg)
	if err := m.Unpack(rb); err != nil {
		return NewDnsError(strconv.FormatUint(uint64(m.Id), 10), ErrDnsBadResponseMessage, "Bad response message: '%s'", err.Error())
	}

	if r != nil && r.Rcode != dns.RcodeSuccess {
		return NewDnsError(strconv.FormatUint(uint64(m.Id), 10), ErrDnsUpdateFailed, "DNS update failed: '%v'", r)
	}
	return nil
}

func (p *pooledUdpDnsGate) Query(typ, key string) ([]dns.RR, error) {
	return nil, nil
}
