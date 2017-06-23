package director

import (
	"git.reaxoft.loc/infomir/director/dnsgate"
	"strings"
	"strconv"
	"fmt"
	"encoding/json"
	"unicode"
	"github.com/miekg/dns"
)

const (
	ErrDirWrongPort   = "director_wrong_port"
	ErrDirWrongSrvName = "director_wrong_srv_name"
	ErrDirWrongSrvType = "director_wrong_srv_type"
)

type DirectorError struct {
	Code string
	Msg   string
	MsgId string
}

func (e *DirectorError) Error() string {
	return fmt.Sprintf("Director error:  code='%s'  msg = '%s'", e.Code, e.Msg)
}

func (e *DirectorError) Json() []byte {
	j, _ := json.Marshal(map[string]string{
		"code":   e.Code,
		"msg":    e.Msg,
	})
	return j
}

func NewDirectorError(code string, msg string, a ...interface{}) *DirectorError {
	return &DirectorError{Code: code, Msg: fmt.Sprintf(msg, a...)}
}
type Director struct {
	gate dnsgate.DnsGate
	domain string
}

func NewDirector(domain, server, keypath string) (*Director, error) {
	parts := strings.Split(server, ":")
	var port uint16
	if len(parts) == 2 {
		u64, e := strconv.ParseUint(parts[1], 10, 16)
		if e != nil {
			return nil, NewDirectorError(ErrDirWrongPort, "Wrong DNS port specified '%s'", parts[1])
		}
		port = uint16(u64)
	} else {
		port = 53
	}
	dg, e := dnsgate.NewPooledUdpDnsGate(parts[0], port, keypath)
	if e != nil {
		return nil, e
	}
	return &Director{gate: dg, domain: domain}, nil
}

func (d *Director) attachSrvToType(srvType, srvName string) (*dns.PTR, error) {
	if !strings.HasSuffix(srvName, srvType) {
		return nil, NewDirectorError(ErrDirWrongSrvName, "Service name must start with a service type")
	}

	if e := validateSrvType(srvType); e != nil {
		return nil, e
	}

	if e := validateSrvNameWithoutType(strings.TrimSuffix(srvName, srvType)); e != nil {
		return nil, e
	}

	ptr := new(dns.PTR)
	ptr.Hdr = dns.RR_Header{srvType, dns.TypePTR, dns.ClassINET, 0, 0}
	ptr.Ptr = srvName
	return ptr, nil
}

func isNotAllowedCharacter(c rune) bool {
	return !unicode.IsLetter(c) && !unicode.IsNumber(c) && c != '_'
}

func validateSrvType(srvType string) error {
	if srvType == "" {
		return NewDirectorError(ErrDirWrongSrvType, "Service type is empty")
	}

	parts := strings.Split(srvType, ".")
	for _, p := range parts {
		if pos := strings.IndexFunc(p, isNotAllowedCharacter); pos != -1 {
			return NewDirectorError(ErrDirWrongSrvType, "Service type contains not allowed character '%s'", p[pos:pos + 1])
		}
		if p[0] != '_' {
			return NewDirectorError(ErrDirWrongSrvType, "Service type's parts must start with '_'")
		}
	}
	return nil
}

func validateSrvNameWithoutType(srvName string) error {
	if srvName == "" {
		return NewDirectorError(ErrDirWrongSrvName, "Service name coincides with a service type")
	}
	if pos := strings.IndexFunc(srvName, isNotAllowedCharacter); pos != -1 {
		return NewDirectorError(ErrDirWrongSrvType, "Starting part of a service name contains not allowed character '%s'", srvName[pos:pos + 1])
	}
	if srvName[0] == '_' {
		return NewDirectorError(ErrDirWrongSrvType, "Service name mut not start with '_'")
	}
	return nil
}

