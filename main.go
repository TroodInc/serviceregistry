package main

import (
	"fmt"
	"git.reaxoft.loc/infomir/director/http"
	"git.reaxoft.loc/infomir/director/logger"
	"log"
	"os"
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

//Main function runs Director server. The following options are avaliable:
// -a - address on which to run server. Default value is "127.0.0.1"
// -p - port on which to run server. Default value is 8080.
// -r - path root to use. Default value is "/director".
// -d - base domain of all services. Default value is "changeme".
// --dns-s - DNS server address. Default value is "changeme".
// --dns-pk - private key to sign command for DNS (RFC2931).
//Default value is "./dns.private".
// --log-file - log file path for a log output. By default the log output is stdout.
// --log-level - logging level. Possible values: panic, fatal, error, warn, info, debug. By default "info".
//Run example: ./director -a 172.25.0.144 -d cust.rxt --dns-s 172.25.0.160:53 --dns-pk /Users/szaytsev/Kszaytsev.cust.rxt.+008+33265.private --log-file ./director.log --log-level debug
//
//Emaple of DNS configuration: https://0x2c.org/rfc2136-ddns-bind-dnssec-for-home-router-dynamic-dns/
//Example of the command to generate dns-pk: dnssec-keygen -C -r /dev/urandom -a RSASHA256 -b 2048 -n HOST -T KEY ivanov.cust.rxt
func main() {
	var srv = http.NewServer("127.0.0.1", "8080", "/director", "changeme", "changeme", "./dns.private")
	var logfile *os.File
	defer func() {
		if logfile != nil {
			logfile.Close()
		}
	}()
	opts := map[string]OptsDesc{
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
		"-d": {1, func(p []string) error {
			srv.SetDomain(p[0])
			return nil
		}},
		"--dns-s": {1, func(p []string) error {
			srv.SetDnsServer(p[0])
			return nil
		}},
		"--dns-pk": {1, func(p []string) error {
			srv.SetDnsPk(p[0])
			return nil
		}},
		"--log-file": {1, func(p []string) error {
			var err error
			if logfile, err = os.OpenFile(p[0], os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644); err != nil {
				return err
			}
			logger.SetOut(logfile)
			log.Printf("Set log output to '%s'\n", p[0])
			return nil
		}},
		"--log-level": {1, func(p []string) error {
			return logger.SetLevel(p[0])
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

	logger.Info("Starting director server...")
	srv.Run()
}
