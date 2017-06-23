package dnsgate

import (
	"git.reaxoft.loc/infomir/director/logger"
	"github.com/julienschmidt/httprouter"
	"github.com/miekg/dns"
	"net/http"
)

type DirectorServer struct {
	addr, port, root string
	s                *http.Server
}

func New(a, p, r string) *DirectorServer {
	return &DirectorServer{addr: a, port: p, root: r}
}

func (ds *DirectorServer) SetAddr(a string) {
	ds.addr = a
}

func (ds *DirectorServer) SetPort(p string) {
	ds.port = p
}

func (ds *DirectorServer) SetRoot(r string) {
	ds.root = r
}

func (ds *DirectorServer) Run() {
	dgate, err := NewPooledUdpDnsGate("172.25.0.160", 53, "/Users/szaytsev/Kszaytsev.cust.rxt.+008+33265.private")
	if err != nil {
		logger.Error("Failed to create connection pool: %s", err.Error())
		panic(err)
	}
	/*	r, err := dns.NewRR("test6.cust.rxt 86400 IN A 172.25.0.43")
		if err != nil {
			logger.Error("Failed to create rr: %s", err.Error())
			panic(err)
		}

		if err := dgate.AddSRV("cust.rxt.", []dns.RR{r}); err != nil {
			panic(err)
		}
		logger.Debug("Successful!!")*/

	rrs, err := dgate.Query(dns.TypeA, "test6.cust.rxt.")
	if err != nil {
		panic(err)
	}
	logger.Debug("len: %d", len(rrs))

	for _, r := range rrs {
		logger.Debug("%s", r)
	}

	router := httprouter.New()
	if router.RedirectTrailingSlash {
		return
	}
}
