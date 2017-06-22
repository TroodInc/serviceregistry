package dnsgate

import (
	"github.com/miekg/dns"
)

type Client struct {
	*dns.Client
}
