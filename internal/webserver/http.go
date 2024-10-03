package webserver

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fileserver/pkg/exterror"
	"fileserver/pkg/fileserver"
	"fileserver/pkg/fileserver/shared"
	"fileserver/pkg/pull"
	"fmt"
	"golang.org/x/crypto/acme/autocert"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const MaxInt64 = ^int64(0)
const charsetUTF8 = "charset=UTF-8"
const MIMEApplicationJSON = "application/json"
const MIMEApplicationJSONCharsetUTF8 = MIMEApplicationJSON + "; " + charsetUTF8

func NewHttp(fs *fileserver.FileServer) *Http {
	return &Http{
		fs: fs,
		wg: &sync.WaitGroup{},
	}
}

const PingHandler = "ping"

var HandlerNames = []string{PingHandler}

type Http struct {
	fs          *fileserver.FileServer
	srv         *http.Server
	certManager autocert.Manager
	wg          *sync.WaitGroup
}

// Start start http server
func (t *Http) Start() error {
	if t.fs.Config().Ssl {
		// create the autocert.Manager with domains and path to the cache
		t.certManager = autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(t.fs.Config().Domains...),
		}
		dir := cacheDir()
		if dir != "" {
			t.certManager.Cache = autocert.DirCache(dir)
		}

		// create the server itself
		t.srv = &http.Server{
			Addr: t.fs.Config().SecureAddr,
			TLSConfig: &tls.Config{
				GetCertificate: t.certManager.GetCertificate,
			},
		}
		t.wg.Add(1)
		go func() {
			slog.Info("Serving request/https for domains: %+v", t.fs.Config().Domains)

			// serve HTTP, which will redirect automatically to HTTPS
			h := t.certManager.HTTPHandler(nil)
			if err := http.ListenAndServe(t.fs.Config().Addr, h); err != nil {
				slog.Error("ListenAndServe: %v", err)
			}
			t.wg.Done()
		}()
		if err := t.srv.ListenAndServeTLS("", ""); err != nil {
			slog.Error("ListenAndServeTLS: %v", err)
			return err
		}
	} else {
		t.wg.Add(1)
		go func() {

			mux := http.NewServeMux()

			mux.Handle("/stop", t.get(t.restricted(t.final(t.Stop))))
			mux.Handle("/ping", t.get(t.final(t.Ping)))
			// {...} require Go 1.22 or never
			mux.Handle("/mkdir/{path...}", t.get(t.restricted(t.final(t.Mkdir))))
			mux.Handle("/upload/{path...}", t.post(t.restricted(t.final(t.Upload))))
			mux.Handle("/list/{path...}", t.get(t.final(t.List)))
			mux.Handle("/download/{path...}", t.each([]string{http.MethodGet, http.MethodHead}, t.final(t.Download)))
			mux.Handle("/remove/{path...}", t.each([]string{http.MethodGet, http.MethodHead}, t.final(t.Remove)))
			mux.Handle("/removeall/{path...}", t.each([]string{http.MethodGet, http.MethodHead}, t.final(t.RemoveAll)))

			http.NewServeMux()
			t.srv = &http.Server{
				Addr:    t.fs.Config().Addr,
				Handler: mux,
			}
			if strings.HasSuffix(t.fs.Config().Addr, ":") {

			}
			ips, err := ipAddresses()
			if err != nil {
				slog.Warn("ipAddresses: %v", err)
			}
			for _, ip := range ips {
				if strings.Index(ip, "::") > -1 {
					slog.Info("Listen address: http://["+ip+"]"+t.fs.Config().Addr, ip, t.fs.Config().Addr)

				} else {
					slog.Info("Listen address: http://" + ip + t.fs.Config().Addr)
				}
			}
			if err := t.srv.ListenAndServe(); err != nil {
				slog.Error("ListenAndServe", "err", err)
			}

			//if err := request.ListenAndServe(t.Config().Addr, nil); err != nil {
			//	log.Printf("ERR: %v", err)
			//}
			t.wg.Done()

		}()
	}

	t.wg.Wait()
	return nil
}

// Stop server http with authentication using bearer token
// response:
// 400 - I don't understand what you mean, maybe not this http method?
func (t *Http) Stop(client Client) error {
	t.srv.Shutdown(context.Background())
	return Ok()
}

// Ping send response pong
// response:
// 200
// 400 - I don't understand what you mean, maybe not this http method?
func (t *Http) Ping(client Client) error {
	return ApplyMessage(client, "pong")
}

// MkDir create (virtual) directory with authentication using bearer token
//
//
// parameters after question mark are optionals
//
// /mkdir/<path>
//
// Authorization: Bearer <apikey>
//
// example:
//		/mkdir/john/invoices
//		/mkdir/john/invoices/2024/07
//		/mkdir/john/others
//	    /mkdir/other
//
// response:
// 200 - directory was created = <path>
// 400 - I don't understand what you mean, maybe not this http method?
// 401 - you are not provided authentication token or not match
// 422 - the given parameters are incorrect
// 501 - internal server error (look into logs)
func (t *Http) Mkdir(client Client) error {
	if err := t.fs.MkDir(client.Request().PathValue("path")); err != nil {
		return err
	}

	return Ok()

}

// List return list of matching items, you can use wildcard (star character)
// for matching anything or space for single character
//
//
// parameters after question mark are optionals
//
// /list/{path}
//
// Authorization: Bearer <apikey>
//
// example:
//		/mkdir/john/invoices
//		/mkdir/john/invoices/2024/07
//		/mkdir/john/others
//	    /mkdir/other
//
// response:
// 200 - directory was created = <path>
// 400 - I don't understand what you mean, maybe not this http method?
// 401 - you are not provided authentication token or not match
// 422 - the given parameters are incorrect
// 501 - internal server error (look into logs)
func (t *Http) List(client Client) error {
	var include shared.FileType
	var limit int
	var pth string
	var useWildcard bool
	// must use this helper functions for wildcard (bug in go)
	if p, err := getUriSuffix(client, "/list/"); err != nil {
		return err
	} else {
		pth = p
	}

	pth = strings.ReplaceAll(pth, " ", "?")

	if strings.Index(pth, "?") > -1 || strings.Index(pth, "*") > -1 {
		useWildcard = true
	}

	if v := client.ParamValues("include"); len(v) > 0 {
		for _, v := range v {
			switch strings.ToLower(v) {
			case "file":
				include = include ^ shared.File
				break
			case "folder":
				include = include ^ shared.Folder
				break
			}
		}
	}
	if limitStr := client.ParamValue("limit"); len(limitStr) > 0 {
		if val, err := strconv.ParseInt(limitStr, 10, 32); err != nil {
			return exterror.NewUnprocessableEntityWrap(err).SetComment("filed limit error")
		} else {
			if val < 0 {
				return exterror.NewUnprocessableEntityWrap(err).SetComment("field limit can't be below zero")
			}
			limit = int(val)
		}
	}

	items := sliceOfItem.Get()
	defer sliceOfItem.Put(items)

	if err := t.fs.List(client.IsAuthorized(), pth, useWildcard, include, limit,
		func(key string, fileInfo *shared.FileInfo) (bool, *exterror.Error) {
			items = append(items, shared.Item{key, fileInfo})
			return true, nil
		}); err != nil {
		return err
	}

	return OkJson(client, items)
}

// Upload receive uploading file with authentication using bearer token (
//
// parameters after question mark are optionals
//
// /upload/<filename_with_path>?name=<original_file_name>&comment=<string>&expire=<format>&hash=<string>
// hash: if you want to protect the file from public access, set a password
// expire: period after which the file is to be deleted, no parameter means the file will never expire
//         enter a numerical value and the ending; year, month, week, day, hour, minute or second
//         examples:
//				expire=1day
//				expire=10year
//
// You can also provide the name, comment, expire and hash fields instead of the URL in the http request headers:
// X-Comment: <value>
// X-Original-Name: <value>
// X-Expire-After: <value>
// X-Hash: <value>
//
// Authorization: Bearer <apikey>
//
// If you provide values directly in the URL and in the headers of HTTP requests, the values from the headers are given more weight.
//
// response:
// 200 - file was uploaded and saved as key = <filename_with_path>
// 400 - I don't understand what you mean, maybe not this http method?
// 401 - you are not provided authentication token or not match
// 422 - the given parameters are incorrect
// 501 - internal server error (look into logs)
func (t *Http) Upload(client Client) error {

	filename := client.Request().PathValue("path")
	contentLenStr := client.Request().Header.Get("Content-Length")
	if len(contentLenStr) == 0 {
		return exterror.NewUnprocessableEntity().SetComment("Content-Length header is empty")
	}

	contentLength, err := strconv.ParseInt(contentLenStr, 10, 64)
	if err != nil {
		return exterror.NewUnprocessableEntity().SetComment(fmt.Sprintf("Content-Length header is not a number: %v", err))
	} else {
		if contentLength == 0 {
			return exterror.NewUnprocessableEntity().SetComment("Content-Length header is zero")
		}
		if t.fs.Config().MaxUploadSize > 0 {
			if contentLength > t.fs.Config().MaxUploadSize {
				return exterror.NewUnprocessableEntity().SetComment("Max upload limit reached")
			}
		}

	}
	var reader io.Reader
	contentType := strings.Split(client.Request().Header.Get("Content-type"), ";")

	options := fileserver.Options{
		Comment:      client.ParamValue("comment"),
		OriginalName: client.ParamValue("name"),
		ExpireAfter:  client.ParamValue("expire"),
		Hash:         client.ParamValue("hash"),
	}

	if val := client.HeaderValue("X-Comment"); len(val) > 0 {
		options.Comment = val
	}
	if val := client.HeaderValue("X-Original-Name"); len(val) > 0 {
		options.OriginalName = val
	}
	if val := client.HeaderValue("X-Expire-After"); len(val) > 0 {
		options.ExpireAfter = val
	}

	if val := client.HeaderValue("X-Hash"); len(val) > 0 {
		options.Hash = val
	}
	switch contentType[0] {
	// curl -X POST --data-binary @/path/folder http://127.0.0.1:18080/upload
	case `application/x-www-form-urlencoded`:
		reader = client.Request().Body
		defer client.Request().Body.Close()
		break

		// curl -v -X POST  -F "file=@path_to_file" http://127.0.0.1:18080/upload/yourfilename
	case `multipart/form-data`:
		if file, _, err := client.Request().FormFile("file"); err != nil {
			return err
		} else {

			if fn := client.Request().FormValue("filename"); len(fn) > 0 {
				options.OriginalName = fn
			}
			//if ct, err := DetectContentType(fn, file); err != nil {
			//	return err
			//} else {
			//	detectedContentType = ct
			//}
			reader = file
			defer file.Close()
		}
		break
		// curl -v -X POST -H  'Content-Type: application/octet-stream' --data-binary @/home/malumar/gopls.log http://127.0.0.1:18080/upload/pliczek
	default:
		options.ContentType = contentType[0]

		reader = client.Request().Body
		defer client.Request().Body.Close()
	}

	if size, fn, err := t.fs.StoreFile(reader, contentLength, filename, &options); err != nil {

		return err
	} else {
		client.AppendLog(fmt.Sprintf("file uploaded bytes %v to %v", size, fn))
	}

	return Ok()

}

// Download download file, use bearer authentication or hash if was set when the file was uploaded (
//
// parameters after question mark are optionals
//
// /download/<filename_with_path>?hash=<hash>
// hash: if the file was secured during shipment, enter the hash value in the URL field or header
//
// You can also provide the hash field instead of the URL in the http request headers:
// X-Hash: <value>
//
// If you provide values directly in the URL and in the headers of HTTP requests, the values from the headers are given more weight.
//
// response:
// 200 - file was uploaded and saved as key = <filename_with_path>
// 400 - I don't understand what you mean, maybe not this http method?
// 401 - you are not provided authentication token or not match
// 404 - file not found or was expired
// 422 - the given parameters are incorrect
// 501 - internal server error (look into logs)
func (self *Http) Download(client Client) error {
	key := client.Request().PathValue("path")
	// delete if expired
	fi, err := self.fs.GetFileInfo(key, true)
	if err != nil {
		return err
	}

	hash := client.ParamValue("hash")
	if val := client.HeaderValue("X-Hash"); len(val) > 0 {
		hash = val
	}
	r, err := self.fs.GetFileReaderIfAuthorized(fi, hash)
	if err != nil {
		return err
	}
	defer func() {
		if closer, ok := r.(io.Closer); ok {
			closer.Close()
		}
	}()
	client.Header().Set("Content-Length", fi.Size)
	client.Header().Set("Content-Type", fi.ContentType)

	var pt time.Time
	if val, err := time.Parse(shared.TimeFormat, fi.UploadDateTime); err != nil {
		slog.Warn("key %s have wrong time format %v: %v", key, fi.UploadDateTime, err)
		pt = time.Now()
	} else {
		pt = val
	}

	if client.Request().Method == http.MethodHead {
		return Ok()
	}

	return serveContent(client, fi.Name, pt, r)
}

// Remove single file (not directory), use bearer authentication
//
// /remove/<filename_with_path>
//
// response:
// 200 - file was remove
// 400 - I don't understand what you mean, maybe not this http method?
// 401 - you are not provided authentication token or not match
// 404 - file not found or was expired
// 422 - the given parameters are incorrect (e.g. if you want to remove directory use RemoveAll instead)
// 501 - internal server error (look into logs)
func (self *Http) Remove(client Client) error {
	return self.fs.Remove(client.Request().PathValue("path"))
}

// RemoveAll delete recursively all folder, subfolder and files in that directories, use bearer authentication
//
// /removeall/<filename_with_path>
//
// response:
// 200 - file was remove
// 400 - I don't understand what you mean, maybe not this http method?
// 401 - you are not provided authentication token or not match
// 404 - file not found or was expired
// 422 - the given parameters are incorrect (e.g. if you want to remove directory use RemoveAll instead)
// 501 - internal server error (look into logs)
func (self *Http) RemoveAll(client Client) error {

	var pth string
	var useWildcard bool
	if p, err := getUriSuffix(client, "/removeall/"); err != nil {
		return err
	} else {
		pth = p
	}

	pth = strings.ReplaceAll(pth, " ", "?")

	if strings.Index(pth, "?") > -1 || strings.Index(pth, "*") > -1 {
		useWildcard = true
	}

	return self.fs.RemoveAll(pth, useWildcard)
}

// Handler first middleware in chain
func (t *Http) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if r, ok := writer.(*requestImpl); ok {
			r.request = request

		}
	})

}

func (t *Http) post(next http.Handler) http.Handler {
	return t.each([]string{http.MethodPost}, next)
}

func (t *Http) get(next http.Handler) http.Handler {
	return t.each([]string{http.MethodGet}, next)
}

func (t *Http) delete(next http.Handler) http.Handler {
	return t.each([]string{http.MethodDelete}, next)
}

func (t *Http) patch(next http.Handler) http.Handler {
	return t.each([]string{http.MethodPatch}, next)
}

func (t *Http) put(next http.Handler) http.Handler {
	return t.each([]string{http.MethodPut}, next)
}

func (t *Http) each(methods []string, next http.Handler) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if t.fs.Config().MaxUploadSize == 0 {
			r.ParseMultipartForm(MaxInt64)
			//r.Body = http.MaxBytesReader(w, r.Body, MaxInt64)
		} else {
			r.ParseMultipartForm(t.fs.Config().MaxUploadSize)
			//r.Body = http.MaxBytesReader(w, r.Body, t.fs.Config().MaxUploadSize)
		}

		ri := requestImpl{ResponseWriter: w, request: r, ip: readUserIp(r)}

		var wrongMethod bool
		if len(methods) > 0 {
			wrongMethod = true
			for _, method := range methods {
				if method == r.Method {
					wrongMethod = false
					next.ServeHTTP(&ri, r)
					break
				}
			}
		}
		if wrongMethod {
			http.Error(&ri, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		}

		slog.Info("request",
			"ip", ri.ip,
			"port", ri.port,
			"method", r.Method,
			"path", r.URL,
			"protocol", r.Proto,
			"status", ri.status,
			"bytes", ri.written,
			"ref", r.Referer(),
			"agent", r.UserAgent(),
			"debug", ri.debug,
		)

		/*
			log.Printf("INFO: %s:%s %s %d %d %q %q %q", ri.ip, ri.port,

				fmt.Sprintf("%s %s %s", r.Method, r.URL, r.Proto),
				ri.status,
				ri.written,
				r.Referer(),
				r.UserAgent(),
				ri.debug,
			)
		*/
	})

}

/*
func JSONHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contentType := r.Header.Get("Content-Type")

		if contentType != "" {
			mt, _, err := mime.ParseMediaType(contentType)
			if err != nil {
				http.Error(w, "Malformed Content-Type header", http.StatusBadRequest)
				return
			}

			if mt != "application/json" {
				http.Error(w, "Content-Type header must be application/json", http.StatusUnsupportedMediaType)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

*/

// restricted middleware convert request to semi framework using in http server
// must be last in chain of real handler
// e.g. server.Handler(server.post(server.restricted(server.final(server.CommandX))))
func (t *Http) final(handler func(client Client) error) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := w.(Client)
		if err := handler(c); err != nil {
			if er, ok := err.(*exterror.Error); ok {
				if c.IsHeaderSent() {
					slog.Error("final", er.Error())
				} else {
					ApplyError(c, err)
				}

			} else {

				if c.IsHeaderSent() {
					slog.Error("final", err)
				} else {
					ApplyError(c, err)
				}
			}
		} else {
			if !c.IsHeaderSent() {
				ApplyMessage(c, "OK")
			}
		}
	})
}

// restricted middleware requiring use authentication with bearer token
func (t *Http) restricted(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		val := r.Header.Get("Authorization")

		if len(val) <= 8 {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		if slice := strings.Split(val, " "); len(slice) != 2 {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		} else {

			if slice[0] == "Bearer" && len(slice[1]) > 0 && slice[1] == t.fs.GetApiKey() {
				slog.Info("Authorized ", "ip", readUserIp(r))
				if c, ok := w.(*requestImpl); ok {
					c.SetAuthorized(true)
				}
			} else {
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

func serveContent(client Client, filename string, modTime time.Time, r io.ReadSeeker) error {
	if client.Request().Method == http.MethodHead {
		return Ok()
	}
	http.ServeContent(client, client.Request(), filename, modTime, r)
	return Ok()
}

func Ok() error {
	return nil
}

func OkJson(client Client, data interface{}) error {
	return ApplyJson(http.StatusOK, client, data)
}

// ApplyJson return json object to client
func ApplyJson(code int, client Client, obj interface{}) error {
	if obj != nil {
		dat, err := json.Marshal(obj)
		if err != nil {
			return exterror.NewInternalServerWrap(err)
		}
		return ApplyJsonBlob(code, client, dat)
	} else {

		return Ok()
	}
	// client.Write(da)
}

func ApplyJsonBlob(code int, client Client, b []byte) error {
	return ApplyBlob(code, client, MIMEApplicationJSONCharsetUTF8, b)
}

func ApplyBlob(code int, client Client, contentType string, b []byte) error {
	client.WriteHeader(code)
	client.SetHeader("Content-Type", contentType)
	client.SetHeader("X-Content-Type", contentType)
	client.SetHeader("Content-Length", strconv.Itoa(len(b)))
	client.Write(b)
	return nil

}

func ApplyError(client Client, err error) {
	if err == nil {
		client.WriteHeader(http.StatusInternalServerError)
		slog.Error("ApplyError require error value")
	}
	if val, ok := err.(*exterror.Error); ok {
		if val == nil {
			ApplyMessage(client, "OK")
			return
		}

		if val.Code() == 0 {
			client.WriteHeader(http.StatusInternalServerError)
			slog.Error("ApplyError require code value")
		} else {
			client.WriteHeader(val.Code())
		}

		if msg := val.Error(); len(msg) > 0 {
			client.Write([]byte(msg))
		}

		if ce := val.Cause(); ce != nil {
			client.AppendLog("%v", ce.Error())
		}

	} else {
		client.WriteHeader(http.StatusBadRequest)
		slog.Error("ApplyError %v", err)

	}
}

func ApplyMessage(client Client, msg string) error {
	client.WriteHeader(http.StatusOK)
	client.Write([]byte(msg))
	return nil
}

type requestImpl struct {
	http.ResponseWriter
	authorized  bool
	status      int
	written     int64
	headerSent  bool
	ip          string
	port        string
	debug       string
	paramValues map[string][]string
	request     *http.Request
}

func (self *requestImpl) Request() *http.Request {
	return self.request
}

func (self *requestImpl) Ip() string {
	return self.ip
}

func (self *requestImpl) Port() string {
	return self.port
}

func (self *requestImpl) Write(p []byte) (n int, err error) {
	if !self.headerSent {
		self.WriteHeader(http.StatusOK)
	}
	if self.request.Method == http.MethodHead {
		return 0, nil
	}

	n, err = self.ResponseWriter.Write(p)
	self.written += int64(n)
	return
}

func (self *requestImpl) WriteHeader(code int) {
	self.ResponseWriter.WriteHeader(code)
	if self.headerSent {
		return
	}
	self.headerSent = true
	self.status = code

}

func (self *requestImpl) IsHeaderSent() bool {
	return self.headerSent
}

func (self *requestImpl) HaveDebugLog() bool {
	return len(self.debug) > 0
}
func (self *requestImpl) SetHeader(name, value string) {
	self.ResponseWriter.Header().Set(name, value)
}
func (self *requestImpl) SetAuthorized(value bool) {
	self.authorized = true
}
func (self *requestImpl) IsAuthorized() bool {
	return self.authorized
}

func (self *requestImpl) HeaderValue(name string) string {
	if val := self.Header().Values(name); len(val) > 0 {
		return val[0]
	}

	return ""
}
func (self *requestImpl) ParamValue(name string) string {
	if val := self.ParamValues(name); len(val) > 0 {
		return val[0]
	}
	return ""
}

// ParamValues return values of given parameter name in URL Query (after question mark)
func (self *requestImpl) ParamValues(name string) []string {
	if self.paramValues == nil {
		self.paramValues = self.Request().URL.Query()
		if self.paramValues == nil {
			self.paramValues = make(map[string][]string)
		}
	}
	if val, ok := self.paramValues[name]; ok {
		return val
	}

	return nil
}
func (self *requestImpl) AppendLog(format string, arg ...interface{}) {
	self.debug += fmt.Sprintf(format, arg...)
}

func readUserIp(r *http.Request) string {
	IPAddress := r.Header.Get("X-Real-Ip")
	if IPAddress == "" {
		IPAddress = r.Header.Get("X-Forwarded-For")
	}
	if IPAddress == "" {
		IPAddress = r.RemoteAddr
	}
	return IPAddress

}

// i.e. http://example.com/file/filename
// afterSubstr = "/file/"
// return "filename"
func getUriSuffix(client Client, afterSubstr string) (string, *exterror.Error) {
	name, err := url.QueryUnescape(client.Request().URL.Path)
	if err != nil {
		return "", exterror.NewNotFoundWrap(err)
	}

	idx := strings.Index(name, afterSubstr)
	if idx == -1 {
		return "", exterror.NewNotFoundWrap(fmt.Errorf("getUriSuffix %s not found", afterSubstr))
	}
	if len(afterSubstr) == 0 {
		idx = len(afterSubstr) - 1
	} else {
		idx = idx + len(afterSubstr)
	}
	if idx > len(name) {
		return "", exterror.NewNotFoundWrap(fmt.Errorf("1 getUriSuffix %s not found", afterSubstr))
	}

	return name[idx:], nil
}

// cacheDir makes a consistent cache directory inside /tmp. Returns "" on error.
func cacheDir() (dir string) {
	if u, _ := user.Current(); u != nil {
		dir = filepath.Join(os.TempDir(), "cache-golang-autocert-"+u.Username)
		if err := os.MkdirAll(dir, 0700); err == nil {
			return dir
		}
	}
	return ""
}

// ipAddresses return all addresses ip mounted on serve
func ipAddresses() ([]string, error) {
	var ret []string
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	// handle err
	for _, i := range ifaces {
		addrs, err := i.Addrs()
		if err != nil {
			slog.Error("can't get information about a address %v", err)
			continue
		}

		for _, addr := range addrs {
			switch v := addr.(type) {
			case *net.IPNet:

				ret = append(ret, v.IP.String())
			case *net.IPAddr:
				ret = append(ret, v.IP.String())
			}

		}
	}
	return ret, nil
}

type Client interface {
	http.ResponseWriter
	Request() *http.Request
	Ip() string
	Port() string
	IsHeaderSent() bool
	AppendLog(format string, args ...interface{})
	HaveDebugLog() bool
	ParamValue(name string) string
	ParamValues(name string) []string
	HeaderValue(name string) string
	SetHeader(name, value string)
	SetAuthorized(bool)
	IsAuthorized() bool
}

var sliceOfItem = pull.New(func() []shared.Item {
	return make([]shared.Item, 0, 1024)
}, func(val []shared.Item) []shared.Item {
	for i, _ := range val {
		val[i].File = nil
		val[i].Key = ""
	}
	val = val[:0]
	return val
})
