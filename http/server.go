package http

import (
	"encoding/json"
	"fmt"
	"git.reaxoft.loc/infomir/director/core"
	"git.reaxoft.loc/infomir/director/logger"
	"github.com/julienschmidt/httprouter"
	"io"
	"mime"
	"net/http"
	"net/textproto"
	"net/url"
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
	addr, port, root, domain, dnsserver, dnspk string
	s                                          *http.Server
}

func NewServer(a, p, r, d, ds, dpk string) *DirectorServer {
	return &DirectorServer{addr: a, port: p, root: r, domain: d, dnsserver: ds, dnspk: dpk}
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

func (ds *DirectorServer) SetDomain(d string) {
	ds.domain = d
}

func (ds *DirectorServer) SetDnsServer(s string) {
	ds.dnsserver = s
}

func (ds *DirectorServer) SetDnsPk(pk string) {
	ds.dnspk = pk
}

func (ds *DirectorServer) Run() {
	dr, err := core.NewDirector(ds.domain, ds.dnsserver, ds.dnspk)
	if err != nil {
		logger.Error("Failed to create connection pool: %s", err.Error())
		panic(err)
	}
	//todo: remove it
	logger.Info("Director created: %v", dr)

	router := httprouter.New()
	router.PUT(ds.root+"/services", CreateDualJsonAction(func(src *json.Decoder, sink *JsonSink, p httprouter.Params, q url.Values) {
		var ds DnsService
		if e := src.Decode(&ds); e != nil {
			logger.Error("Can't decode JSON to DNSService: %s", e.Error())
			sink.pushError(&ServerError{http.StatusBadRequest, ErrBadRequest, "bad JSON: " + e.Error()})
			return
		}
		//todo: process dns service
		/*if o, e := proc.Put(p.ByName("name"), srsc.Value); e != nil {
			sink.pushError(e)
		} else {
			sink.pushGeneric(o)
		}*/
	}))

	router.GET(ds.root+"/service/:type", CreateJsonAction(func(_ io.ReadCloser, js *JsonSink, p httprouter.Params, q url.Values) {
		js.pushError(&ServerError{http.StatusNotImplemented, ErrInternalServerError, "Has not realized yet"})
		//todo: do it
		//return array of DNSService's names
	}))

	router.GET(ds.root+"/service/:type/:name", CreateJsonAction(func(_ io.ReadCloser, js *JsonSink, p httprouter.Params, q url.Values) {
		js.pushError(&ServerError{http.StatusNotImplemented, ErrInternalServerError, "Has not realized yet"})
		//todo: do it
		//return array of DNSService
	}))

	router.DELETE(ds.root+"/service/:type/:name", CreateJsonAction(func(_ io.ReadCloser, js *JsonSink, p httprouter.Params, q url.Values) {
		js.pushError(&ServerError{http.StatusNotImplemented, ErrInternalServerError, "Has not realized yet"})
		//possible query parameters: server, port
		//todo: remove
	}))

	ds.s = &http.Server{
		Addr:           ds.addr + ":" + ds.port,
		Handler:        router,
		ReadTimeout:    60 * time.Second,
		WriteTimeout:   60 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	logger.Info("Director server started.")
	ds.s.ListenAndServe()
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

type DnsService struct {
	Type     string `json:"type"`
	Name     string `json:"name"`
	Server   string `json:"server"`
	Port     string `json:"port"`
	Path     string `json:"path"`
	CacheTtl int    `json:"cachettl"`
	Priority int    `json:"priority"`
	Weight   int    `json:"weight"`
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
