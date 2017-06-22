package server

import (
	"github.com/miekg/dns"
)

type Client struct {
	*dns.Client
}
