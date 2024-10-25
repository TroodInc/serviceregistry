package http

import (
	"context"
	"encoding/json"
	"fmt"
	"git.reaxoft.loc/infomir/director/core"
	"git.reaxoft.loc/infomir/director/logger"
	"github.com/julienschmidt/httprouter"
	"io"
	"log"
	"mime"
	"net/http"
	"net/textproto"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

const (
	ErrUnsupportedMediaType = "unsupported_media_type"
	ErrBadRequest           = "bad_request"
	ErrInternalServerError  = "internal_server_error"
)

type ServerError struct {
	status int
	code   string
	msg    string
}

func (e *ServerError) Error() string {
	return fmt.Sprintf("Server error: status = %d, code = '%s', msg = '%s'", e.status, e.code, e.msg)
}

func (e *ServerError) Json() []byte {
	return marshalError(e.code, e.msg)
}

type DirectorServer struct {
	addr, root, domain     string
	port                   uint16
	dnsserver, dnspk       string
	srvhostname            string
	srvttl                 uint32
	srvpriority, srvweight uint16
	srvtype                string
	basepath               string
	s                      *http.Server
}

func NewServer(a string, p uint16, hostname string, r, d, ds, dpk string) *DirectorServer {
	return &DirectorServer{addr: a, port: p, root: r, domain: d, dnsserver: ds, dnspk: dpk, srvhostname: hostname}
}

func (ds *DirectorServer) SetAddr(a string) {
	ds.addr = a
}

func (ds *DirectorServer) SetPort(p uint16) {
	ds.port = p
}

func (ds *DirectorServer) SetRoot(r string) {
	ds.root = r
}

func (ds *DirectorServer) SetDomain(d string) {
	ds.domain = d
}

func (ds *DirectorServer) SetDnsServer(s string) {
	ds.dnsserver = s
}

func (ds *DirectorServer) SetDnsPk(pk string) {
	ds.dnspk = pk
}

func (ds *DirectorServer) SetSrvHostname(hostname string) {
	ds.srvhostname = hostname
}

func (ds *DirectorServer) SetSrvTtl(ttl uint32) {
	ds.srvttl = ttl
}

func (ds *DirectorServer) SetSrvPriority(priority uint16) {
	ds.srvpriority = priority
}

func (ds *DirectorServer) SetSrvWeight(weight uint16) {
	ds.srvweight = weight
}

type srvinfo struct {
	name, method, path string
}

var services = []*srvinfo{
	&srvinfo{"reg_srv.", "PUT", ""},
	&srvinfo{"get_srvs.", "GET", "/types"},
	&srvinfo{"get_ins.", "GET", "/intances"},
	&srvinfo{"del_srv.", "DELETE", "/types"},
	&srvinfo{"del_ins.", "DELETE", "/names"},
}

func (ds *DirectorServer) newService(info *srvinfo) *director.DnsService {
	return &director.DnsService{
		Name:     info.name + ds.srvtype,
		Server:   ds.srvhostname,
		Port:     ds.port,
		Ttl:      ds.srvttl,
		Priority: ds.srvpriority,
		Weight:   ds.srvweight,
		Params:   map[string]string{"path": ds.basepath + info.path, "method": info.method},
	}
}

func (ds *DirectorServer) regDnsServices(dr *director.Director) error {
	ds.srvtype = "_drt._rest_http." + ds.domain
	ds.basepath = ds.root + "/services"
	for _, si := range services {
		if e := dr.RegDnsSrv(ds.srvtype, ds.newService(si)); e != nil {
			return e
		}
	}
	return nil
}

func (ds *DirectorServer) delDnsServices(dr *director.Director) error {
	for _, si := range services {
		if e := dr.RmInstance(si.name+ds.srvtype, ds.srvhostname, ds.port); e != nil {
			return e
		}
	}
	return nil
}

func getMandatoryQParam(q url.Values, name string) (string, error) {
	v := q.Get(name)
	if v == "" {
		return "", &ServerError{http.StatusBadRequest, ErrBadRequest, "Required query parameter 'name' not found"}
	} else {
		return v, nil
	}
}

func (ds *DirectorServer) Run() {
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	dr, err := director.NewDirector(ds.domain, ds.dnsserver, ds.dnspk)
	if err != nil {
		logger.Error("Failed to create connection pool: %s", err.Error())
		panic(err)
	}

	router := httprouter.New()

	router.PUT(ds.root+"/services/:type", CreateDualJsonAction(func(src *json.Decoder, sink *JsonSink, p httprouter.Params, q url.Values) {
		var ds director.DnsService
		if e := src.Decode(&ds); e != nil {
			logger.Error("Can't decode JSON to object: %s", e.Error())
			sink.pushError(&ServerError{http.StatusBadRequest, ErrBadRequest, "bad JSON: " + e.Error()})
			return
		}

		if e := dr.RegDnsSrv(p.ByName("type"), &ds); e != nil {
			sink.pushError(e)
		} else {
			sink.pushCreated()
		}
	}))

	router.GET(ds.root+"/services/types/:type", CreateJsonAction(func(_ io.ReadCloser, sink *JsonSink, p httprouter.Params, q url.Values) {
		if names, e := dr.FindDnsSrvNames(p.ByName("type")); e != nil {
			sink.pushError(e)
		} else {
			sink.push(names)
		}
	}))

	router.GET(ds.root+"/services/instances/:name", CreateJsonAction(func(_ io.ReadCloser, sink *JsonSink, p httprouter.Params, q url.Values) {
		if instances, e := dr.FindDnsSrvInstances(p.ByName("name")); e != nil {
			sink.pushError(e)
		} else {
			sink.push(instances)
		}
	}))

	router.DELETE(ds.root+"/services/types/:type", CreateJsonAction(func(_ io.ReadCloser, sink *JsonSink, p httprouter.Params, q url.Values) {
		name, err := getMandatoryQParam(q, "name")
		if err != nil {
			logger.Error(err.Error())
			sink.pushError(err)
			return
		}

		if e := dr.RmDnsSrv(p.ByName("type"), name); e != nil {
			sink.pushError(e)
		} else {
			sink.pushEmpty()
		}
	}))

	router.DELETE(ds.root+"/services/instances/:name", CreateJsonAction(func(_ io.ReadCloser, sink *JsonSink, p httprouter.Params, q url.Values) {
		server, err := getMandatoryQParam(q, "server")
		if err != nil {
			logger.Error(err.Error())
			sink.pushError(err)
			return
		}

		sport, err := getMandatoryQParam(q, "port")
		if err != nil {
			logger.Error(err.Error())
			sink.pushError(err)
			return
		}

		port, err := strconv.ParseUint(sport, 10, 32)
		if err != nil {
			logger.Error(err.Error())
			sink.pushError(err)
			return
		}

		if e := dr.RmInstance(p.ByName("name"), server, uint16(port)); e != nil {
			sink.pushError(e)
		} else {
			sink.pushEmpty()
		}
	}))

	ds.s = &http.Server{
		Addr:           ds.addr + ":" + strconv.FormatUint(uint64(ds.port), 10),
		Handler:        router,
		ReadTimeout:    60 * time.Second,
		WriteTimeout:   60 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	logger.Info("Registring director's services in DNS ...")
	if e := ds.regDnsServices(dr); e != nil {
		logger.Error("Filed to registring service: %s", e.Error())
		log.Fatal(e)
	}
	logger.Info("Director's services has been registered")

	go func() {
		logger.Info("Director server listening on http://%s%s", ds.s.Addr, ds.root)
		if err := ds.s.ListenAndServe(); err != http.ErrServerClosed {
			logger.Error("Director server listening and serve failed: %s", err.Error())
			log.Fatal(err)
		}
	}()

	<-stop

	logger.Info("Deleting director's instances of services in DNS ...")
	if e := ds.delDnsServices(dr); e != nil {
		logger.Error("Failed director's instances of services in DNS: %s", e.Error())
	} else {
		logger.Info("Director's instances of services has been deleted")
	}

	logger.Info("Shutting down Director server with %ds timeout ...", 10)
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	ds.s.Shutdown(ctx)
	logger.Info("Directory server gracefully stopped")
}

func marshalError(code, msg string) []byte {
	j, _ := json.Marshal(map[string]string{
		"code": code,
		"msg":  msg,
	})
	return j
}

func returnError(w http.ResponseWriter, e error) {
	w.Header().Set("Content-Type", "application/json")
	switch e := e.(type) {
	case *ServerError:
		w.WriteHeader(e.status)
		w.Write(e.Json())
		return
	case *director.DirectorError:
		/*if e.Code == director.ErrDirWrongSrvNotFound {
			w.WriteHeader(http.StatusNotFound)
		} else {
			w.WriteHeader(http.StatusBadRequest)
		}*/
		w.WriteHeader(http.StatusBadRequest)
		w.Write(e.Json())
		return
	default:
		w.WriteHeader(http.StatusInternalServerError)
		w.Write(marshalError(ErrInternalServerError, e.Error()))
		return
	}
}

//The JSON object sink into the HTTP response.
type JsonSink struct {
	rw http.ResponseWriter
}

//Converts http.ResponseWriter into JsonSink.
func asJsonSink(w http.ResponseWriter) (*JsonSink, error) {
	return &JsonSink{w}, nil
}

//Push an error into JsonSink.
func (js *JsonSink) pushError(e error) {
	returnError(js.rw, e)
}

//Push an JSON object into JsonSink
func (js *JsonSink) pushGeneric(obj map[string]interface{}) {
	if j, e := json.Marshal(obj); e != nil {
		returnError(js.rw, e)
	} else {
		js.rw.Header().Set("Content-Type", "application/json")
		js.rw.WriteHeader(http.StatusOK)
		js.rw.Write(j)
	}
}

func (js *JsonSink) push(i interface{}) {
	if j, e := json.Marshal(i); e != nil {
		returnError(js.rw, e)
	} else {
		js.rw.Header().Set("Content-Type", "application/json")
		js.rw.WriteHeader(http.StatusOK)
		js.rw.Write(j)
	}
}

//Push an emptiness into JsonSink.
func (js *JsonSink) pushEmpty() {
	js.rw.WriteHeader(http.StatusNoContent)
}

func (js *JsonSink) pushCreated() {
	js.rw.WriteHeader(http.StatusCreated)
}

type httpRequest http.Request

//Converts an HTTP request to the JsonSource if the request is valid and contains a valid JSON object in its body.
func (r *httpRequest) asJsonDecoder() (*json.Decoder, error) {
	var smime = r.Header.Get(textproto.CanonicalMIMEHeaderKey("Content-Type"))
	if smime == "" {
		return nil, &ServerError{http.StatusUnsupportedMediaType, ErrUnsupportedMediaType, "content type not found"}
	}
	mm, _, e := mime.ParseMediaType(smime)
	if e != nil {
		return nil, &ServerError{http.StatusBadRequest, ErrBadRequest, e.Error()}
	}
	if mm != "application/json" {
		return nil, &ServerError{http.StatusUnsupportedMediaType, ErrUnsupportedMediaType, "mime type is not of 'application/json'"}
	}
	var body = r.Body
	if body == nil {
		return nil, &ServerError{http.StatusBadRequest, ErrBadRequest, "no body"}
	}

	return json.NewDecoder(body), nil
}

func CreateJsonAction(f func(io.ReadCloser, *JsonSink, httprouter.Params, url.Values)) func(http.ResponseWriter, *http.Request, httprouter.Params) {
	return func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		sink, _ := asJsonSink(w)
		f(r.Body, sink, p, r.URL.Query())
	}
}

func CreateDualJsonAction(f func(*json.Decoder, *JsonSink, httprouter.Params, url.Values)) func(http.ResponseWriter, *http.Request, httprouter.Params) {
	return func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		d, e := (*httpRequest)(r).asJsonDecoder()
		if e != nil {
			returnError(w, e)
			return
		}

		sink, _ := asJsonSink(w)
		f(d, sink, p, r.URL.Query())
	}
}
