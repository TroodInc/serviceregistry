package director

import (
	"bytes"
	"encoding/json"
	"fmt"
	"git.reaxoft.loc/infomir/director/dnsgate"
	"github.com/miekg/dns"
	"strconv"
	"strings"
	"unicode"
)

const (
	ErrDirWrongPort        = "director_wrong_port"
	ErrDirWrongSrvName     = "director_wrong_srv_name"
	ErrDirWrongSrvType     = "director_wrong_srv_type"
	ErrDirWrongTxtString   = "director_wrong_txt_string"
	ErrDirWrongSrvNotFound = "director_srv_not_found"
)

type DirectorError struct {
	Code  string
	Msg   string
	MsgId string
}

func (e *DirectorError) Error() string {
	return fmt.Sprintf("Director error:  code='%s'  msg = '%s'", e.Code, e.Msg)
}

func (e *DirectorError) Json() []byte {
	j, _ := json.Marshal(map[string]string{
		"code": e.Code,
		"msg":  e.Msg,
	})
	return j
}

func NewDirectorError(code string, msg string, a ...interface{}) *DirectorError {
	return &DirectorError{Code: code, Msg: fmt.Sprintf(msg, a...)}
}

type Director struct {
	gate   dnsgate.DnsGate
	domain string
	zone   string
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
	return &Director{gate: dg, domain: domain, zone: domain + "."}, nil
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

func (d *Director) assignSrvToServer(srvName string, server string, port uint16, ttl uint32, priority uint16, weight uint16) (*dns.SRV, error) {
	if e := validateSrvName(srvName); e != nil {
		return nil, e
	}

	srv := new(dns.SRV)
	srv.Hdr = dns.RR_Header{srvName, dns.TypeSRV, dns.ClassINET, ttl, 0}
	srv.Target = server
	srv.Port = port
	srv.Priority = priority
	srv.Weight = weight
	return srv, nil
}

func isNotAllowedTxtKeyCharacter(c rune) bool {
	return c < 0x20 || c > 0x7e || c == 0x3d
}

// *recomended full len is 1300
// *255 is max key-value string length
// *key size is beetwen 1 and 9
// *key character is within range 0x20-0x7E, except 0x3D
// *key is not case sensative
// *value may be absent
// *if there is more than one key of the same name, all keys after first one are discarded
// *txtvers=x
// protovers is protocol version key

func isDigit(c byte) bool {
	return c >= '0' && c <= '9'
}

func (d *Director) addServRules(srvName string, params map[string]string) (*dns.TXT, error) {
	if e := validateSrvName(srvName); e != nil {
		return nil, e
	}

	var str []string = nil
	if len(params) != 0 {
		str = make([]string, 1, len(params))
		var fullLen = 0
		var strLen int
		for k, v := range params {
			if len(k) < 1 || len(k) > 9 {
				return nil, NewDirectorError(ErrDirWrongTxtString, "TXT key must have length between 1 and 9")
			}
			if pos := strings.IndexFunc(srvName, isNotAllowedCharacter); pos != -1 {
				return nil, NewDirectorError(ErrDirWrongTxtString, "TXT key contains a not allowed character")
			}

			strLen = 0
			for i := 0; i < len(v); i++ {
				if v[i] == '\\' {
					i++
					if i+2 < len(v) && isDigit(v[i]) && isDigit(v[i+1]) && isDigit(v[i+2]) {
						i += 2
					}
				}
				strLen++
			}
			strLen += len(k) + 1
			if strLen > 255 {
				return nil, NewDirectorError(ErrDirWrongTxtString, "TXT string exceeded 255 bytes")
			}
			fullLen += strLen + 1

			if fullLen > 1300 {
				return nil, NewDirectorError(ErrDirWrongTxtString, "String section of a TXT resource record exceeded 1300 bytes")
			}
			if k == "txtvers" {
				str[0] = k + "=" + v
			} else {
				str = append(str, k+"="+v)
			}
		}
		if str[0] == "" {
			str = str[1:]
		}
	}

	txt := new(dns.TXT)
	txt.Hdr = dns.RR_Header{srvName, dns.TypeTXT, dns.ClassINET, 0, 0}
	txt.Txt = str
	return txt, nil
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
			return NewDirectorError(ErrDirWrongSrvType, "Service type contains not allowed character '%s'", p[pos:pos+1])
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
		return NewDirectorError(ErrDirWrongSrvName, "Starting part of a service name contains not allowed character '%s'", srvName[pos:pos+1])
	}
	if srvName[0] == '_' {
		return NewDirectorError(ErrDirWrongSrvName, "Service name mut not start with '_'")
	}
	return nil
}

func validateSrvName(srvName string) error {
	if srvName == "" {
		return NewDirectorError(ErrDirWrongSrvName, "Service name is empty")
	}

	if srvName[0] == '_' {
		return NewDirectorError(ErrDirWrongSrvName, "Service name must not start with '_'")
	}

	parts := strings.Split(srvName, ".")
	for i, p := range parts {
		if pos := strings.IndexFunc(p, isNotAllowedCharacter); pos != -1 {
			return NewDirectorError(ErrDirWrongSrvName, "Service name contains not allowed character '%s'", p[pos:pos+1])
		}
		if i > 0 && p[0] != '_' {
			return NewDirectorError(ErrDirWrongSrvName, "Middle service name's parts must start with '_'")
		}
	}
	return nil
}

func (d *Director) findSrv(srvName string) ([]*dns.SRV, *dns.TXT, error) {
	if e := validateSrvName(srvName); e != nil {
		return nil, nil, e
	}

	rrs, e := d.gate.Query(dns.TypeANY, srvName)
	if e != nil {
		return nil, nil, e
	}

	var srvs []*dns.SRV
	var txt *dns.TXT
	for _, rr := range rrs {
		switch t := rr.(type) {
		case (*dns.SRV):
			srvs = append(srvs, t)
		case (*dns.TXT):
			txt = t
		}
	}

	if len(srvs) == 0 {
		return nil, nil, NewDirectorError(ErrDirWrongSrvNotFound, "SRV records not found for service '%s'", srvName)
	}

	if txt == nil {
		return nil, nil, NewDirectorError(ErrDirWrongSrvNotFound, "TXT record not found for service '%s'", srvName)
	}
	return srvs, txt, nil
}

func (d *Director) findByType(srvType string) ([]*dns.PTR, error) {
	if e := validateSrvType(srvType); e != nil {
		return nil, e
	}

	rrs, e := d.gate.Query(dns.TypePTR, srvType)
	if e != nil {
		return nil, e
	}
	ptrs := make([]*dns.PTR, 0, len(rrs))
	for _, rr := range rrs {
		switch t := rr.(type) {
		case (*dns.PTR):
			ptrs = append(ptrs, t)
		}
	}
	return ptrs, nil
}

type DnsService struct {
	Type     string `json:"type"`
	Name     string `json:"name"`
	Server   string `json:"server"`
	Port     uint16 `json:"port"`
	Path     string `json:"path"`
	Ttl      uint32 `json:"Ttl"`
	Priority uint16 `json:"priority"`
	Weight   uint16 `json:"weight"`
}

func (d *Director) withDomain(p string) string {
	b := bytes.NewBufferString(p)
	b.WriteRune('.')
	b.WriteString(d.domain)
	return b.String()
}

func (d *Director) RegDnsSrv(srv *DnsService) error {
	fName := d.withDomain(srv.Name)
	rPtr, err := d.attachSrvToType(d.withDomain(srv.Type), fName)
	if err != nil {
		return err
	}
	rSrv, err := d.assignSrvToServer(fName, d.withDomain(srv.Server), srv.Port, srv.Ttl, srv.Priority, srv.Weight)
	if err != nil {
		return err
	}
	rTxt, err := d.addServRules(fName, map[string]string{"path": srv.Path})
	if err != nil {
		return err
	}
	return d.gate.Add(d.zone, []dns.RR{rPtr, rSrv, rTxt})
}
