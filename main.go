package main

import (
	"fmt"
	"git.reaxoft.loc/infomir/director/http"
	"git.reaxoft.loc/infomir/director/logger"
	"log"
	"os"
	"strconv"
)

type OptsError struct {
	arg, msg string
}

func (e *OptsError) Error() string {
	return fmt.Sprintf("Argument '%s': %s", e.arg, e.msg)
}

func dummyDefHandler() error { return nil }
func mandatoryDefHandler(arg string) func() error {
	return func() error {
		return &OptsError{arg, "is not found"}
	}
}

type OptsDesc struct {
	prmsCnt    int
	handler    func(p []string) error
	defhandler func() error
}

//Main function runs Director server. The following options are avaliable:
// -a - address on which to run server. Default value is ""
// -p - port on which to run server. Default value is 8080.
// -h - hostname of services. Default value is machine hostname.
// -r - path root to use. Default value is "/director".
// -d - base domain of all services. Default value is "changeme".
// --drt-dns-ttl - ttl of DNS records for directory services.
// --drt-dns-p - priority of DNS SRV record for directory services.
// --drt-dns-w - weight of DNS SRV record for directory services.
// --dns-s - DNS server address. Default value is "changeme".
// --dns-pk - private key to sign command for DNS (RFC2931). Default value is "./dns.private".
// --log-file - log file path for a log output. By default the log output is stdout.
// --log-level - logging level. Possible values: panic, fatal, error, warn, info, debug. By default "info".
//Run example: ./director -a 172.25.0.144 -d cust.rxt --dns-s 172.25.0.160:53 --dns-pk /Users/szaytsev/Kszaytsev.cust.rxt.+008+33265.private --log-file ./director.log --log-level debug
//
//Emaple of DNS configuration: https://0x2c.org/rfc2136-ddns-bind-dnssec-for-home-router-dynamic-dns/
//Example of the command to generate dns-pk: dnssec-keygen -C -r /dev/urandom -a RSASHA256 -b 2048 -n HOST -T KEY ivanov.cust.rxt
func main() {
	var srv = http.NewServer("", 8080, "", "/director", "", "", "./dns.private")
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
		}, dummyDefHandler},
		"-p": {1, func(p []string) error {
			port, err := strconv.ParseUint(p[0], 10, 32)
			if err != nil {
				return err
			}
			srv.SetPort(uint16(port))
			return nil
		}, dummyDefHandler},
		"-h": {1, func(p []string) error {
			srv.SetSrvHostname(p[0])
			return nil
		}, func() error {
			hostname, err := os.Hostname()
			if err != nil {
				return err
			}
			srv.SetSrvHostname(hostname)
			return nil
		}},
		"-r": {1, func(p []string) error {
			srv.SetRoot(p[0])
			return nil
		}, dummyDefHandler},
		"-d": {1, func(p []string) error {
			srv.SetDomain(p[0])
			return nil
		}, mandatoryDefHandler("-d")},
		"--dns-s": {1, func(p []string) error {
			srv.SetDnsServer(p[0])
			return nil
		}, mandatoryDefHandler("-dns-s")},
		"--dns-pk": {1, func(p []string) error {
			srv.SetDnsPk(p[0])
			return nil
		}, dummyDefHandler},
		"--log-file": {1, func(p []string) error {
			var err error
			if logfile, err = os.OpenFile(p[0], os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644); err != nil {
				return err
			}
			logger.SetOut(logfile)
			log.Printf("Set log output to '%s'\n", p[0])
			return nil
		}, dummyDefHandler},
		"--log-level": {1, func(p []string) error {
			return logger.SetLevel(p[0])
		}, dummyDefHandler},
	}

	args := os.Args[1:]
	for len(args) > 0 {
		if v, e := opts[args[0]]; e && len(args)-1 >= v.prmsCnt {
			if err := v.handler(args[1 : v.prmsCnt+1]); err != nil {
				log.Fatalln(err)
				os.Exit(127)
			}
			delete(opts, args[0])
			args = args[1+v.prmsCnt:]
		} else {
			log.Fatalf("Wrong argument '%s'", args[0])
			os.Exit(127)
		}
	}

	for _, v := range opts {
		if err := v.defhandler(); err != nil {
			log.Fatalln(err)
			os.Exit(127)
		}
	}

	logger.Info("Starting director server...")
	srv.Run()
}
