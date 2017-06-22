package dnsgate

import (
	"github.com/miekg/dns"
)

type udpDnsGate struct {
	*dns.Client
}
