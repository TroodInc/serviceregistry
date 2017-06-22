package dnsgate

import (
	"github.com/miekg/dns"
)

type udpGate struct {
	*dns.Client
}
