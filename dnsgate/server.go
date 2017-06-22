package dnsgate

import (
	"github.com/julienschmidt/httprouter"
	"net/http"
)

type DirectorServer struct {
	addr, port, root string
	s                *http.Server
}

func New(a, p, r string) *DirectorServer {
	return &DirectorServer{addr: a, port: p, root: r}
}

func (cs *DirectorServer) SetAddr(a string) {
	cs.addr = a
}

func (cs *DirectorServer) SetPort(p string) {
	cs.port = p
}

func (cs *DirectorServer) SetRoot(r string) {
	cs.root = r
}

func (cs *DirectorServer) Run() {
	router := httprouter.New()
	if router.RedirectTrailingSlash {
		return
	}
}
