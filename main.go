package main

import (
	"crypto/rsa"
	"fmt"
	"git.reaxoft.loc/infomir/director/logger"
	"git.reaxoft.loc/infomir/director/server"
	"github.com/miekg/dns"
	"log"
	"os"
	"time"
)

type OptsError struct {
	arg, msg string
}

func (e *OptsError) Error() string {
	return fmt.Sprintf("Wrong argument '%s': %s", e.arg, e.msg)
}

type OptsDesc struct {
	prmsCnt int
	handler func(p []string) error
}

func init() {
	logger.SetOut(os.Stdout)
	logger.SetLevel("debug")
	log.Printf("The logger is initialized: level: '%s', output: '%s'.\n", "debug", "stdout")
}

func main() {
	pubf, e := os.Open("/Users/szaytsev/Kszaytsev.cust.rxt.+008+33265.key")
	if e != nil {
		logger.Error("Can not open public key file: %v", e)
		os.Exit(127)
	}

	pubkey, e := dns.ReadRR(pubf, "Kszaytsev.cust.rxt.+008+33265.key")
	if e != nil {
		logger.Error("Can not parse public key: %v", e)
		os.Exit(127)
	}

	privf, e := os.Open("/Users/szaytsev/Kszaytsev.cust.rxt.+008+33265.private")
	if e != nil {
		logger.Error("Can not open private key file: %v", e)
		os.Exit(127)
	}

	key := pubkey.(*dns.KEY)
	privkey, e := key.ReadPrivateKey(privf, "Kszaytsev.cust.rxt.+008+33265.private")
	if e != nil {
		logger.Error("Can not parse private key file: %v", e)
		os.Exit(127)
	}

	m := new(dns.Msg)
	r, err := dns.NewRR("test.cust.rxt 86400 IN A 172.25.0.43")
	if err != nil {
		logger.Error("Failed to create rr: %s", err.Error())
		os.Exit(127)
	}
	m.SetUpdate("cust.rxt.")
	m.Insert([]dns.RR{r})

	now := uint32(time.Now().Unix())
	sig := new(dns.SIG)
	sig.Hdr.Name = "."
	sig.Hdr.Rrtype = dns.TypeSIG
	sig.Hdr.Class = dns.ClassANY
	sig.Algorithm = key.Algorithm
	sig.SignerName = key.Hdr.Name
	sig.Expiration = now + 300
	sig.Inception = now - 300
	sig.KeyTag = key.KeyTag()

	/*sig.Hdr = dns.RR_Header{"szaytsev.cust.rxt", dns.TypeRRSIG, dns.ClassINET, 14400, 0}
	sig.TypeCovered = r.Header().Rrtype
	sig.Labels = uint8(dns.CountLabel(r.Header().Name))
	sig.OrigTtl = r.Header().Ttl*/

	mb, e := sig.Sign(privkey.(*rsa.PrivateKey), m)
	if e != nil {
		logger.Error("Failed to sign: %v", e)
		os.Exit(127)
	}

	sm := new(dns.Msg)
	if err := sm.Unpack(mb); err != nil {
		logger.Error("Failed to unpack signed message: %v", e)
		os.Exit(127)
	}
	//	m.SetQuestion("vkarpov.cust.rxt.", dns.TypeA)
	//logger.Debug("Start: %s", m.String())

	c := new(dns.Client)

	resp, _, err := c.Exchange(sm, "172.25.0.160:53")

	if resp != nil && resp.Rcode != dns.RcodeSuccess {
		logger.Error("Failed to get an valid answer: %v\n", resp)
	}
	logger.Debug("Got an valid answer: %v\n", resp)

	var srv = server.New("", "8080", "/director")

	var opts = map[string]OptsDesc{
		"-a": {1, func(p []string) error {
			srv.SetAddr(p[0])
			return nil
		}},
		"-p": {1, func(p []string) error {
			srv.SetPort(p[0])
			return nil
		}},
		"-r": {1, func(p []string) error {
			srv.SetRoot(p[0])
			return nil
		}},
	}

	args := os.Args[1:]
	for len(args) > 0 {
		if v, e := opts[args[0]]; e && len(args)-1 >= v.prmsCnt {
			if err := v.handler(args[1 : v.prmsCnt+1]); err != nil {
				log.Fatalln(err)
				os.Exit(127)
			}
			args = args[1+v.prmsCnt:]
		} else {
			log.Fatalf("Wrong argument '%s'", args[0])
			os.Exit(127)
		}
	}

	log.Println("Director server started.")
	srv.Run()
}
