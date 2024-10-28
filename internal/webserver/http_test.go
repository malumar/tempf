package webserver

import (
	"fmt"
	"github.com/gavv/httpexpect/v2"
	"github.com/malumar/tempf/pkg/fileserver"
	"github.com/stretchr/testify/assert"
	"net/http"
	"os"
	"strconv"
	"testing"
	"time"
)

func TestHttpHandler(t *testing.T) {
	cfg := fileserver.DefaultConfig()
	if p, err := os.MkdirTemp("", "httptest"); err != nil {
		t.Error(err)
	} else {
		cfg.Path = p
		fmt.Println(p)
	}
	// allow match all
	cfg.AllowList = []string{"*"}

	fs, err := fileserver.New(cfg)
	assert.NotNil(t, fs)
	assert.NoError(t, err)

	apiKey, aerr := fs.ResetApiKey()
	assert.NoError(t, aerr)

	hh := NewHttp(fs)
	assert.NotNil(t, hh)
	defer hh.Stop(nil)
	go hh.Start()
	// wait a moment
	time.Sleep(time.Millisecond * 10)

	e := httpexpect.WithConfig(httpexpect.Config{
		Client: &http.Client{
			Transport: httpexpect.NewBinder(hh.srv.Handler),
			Jar:       httpexpect.NewCookieJar(),
		},
		Reporter: httpexpect.NewAssertReporter(t),
		Printers: []httpexpect.Printer{
			httpexpect.NewDebugPrinter(t, true),
		},
	})
	assert.NoError(t, err)
	// remember the API key to use in requests that require authorization
	e.Env().Put("api_key", string(apiKey))

	testEcho(e)
}

func testEcho(e *httpexpect.Expect) {

	key := e.Env().GetString("api_key")
	auth := e.Builder(func(req *httpexpect.Request) {
		req.WithHeader("Authorization", "Bearer "+key)
	})

	auth.GET("/stop").Expect().Status(http.StatusOK).
		Body().IsEqual("OK")

	e.GET("/stop").
		WithText("disallow stop server without authorization").
		Expect().Status(http.StatusUnauthorized).
		Body().IsEqual("Unauthorized\n")

	e.GET("/ping").
		Expect().Status(http.StatusOK).
		Body().IsEqual("pong")

	e.POST("/mkdir").
		WithText("disallow to create new dir without name").
		Expect().Status(http.StatusBadRequest).
		Body().IsEqual("Bad Request\n")

	e.POST("/mkdir/test").
		WithText("disallow to create new dir without authorization").
		Expect().Status(http.StatusUnauthorized).
		Body().IsEqual("Unauthorized\n")

	auth.POST("/mkdir/test").
		WithText("disallow to create new dir without slash at end of name").
		Expect().Status(http.StatusUnprocessableEntity).
		Body().IsEqual("key is empty or contains illegal characters")

	auth.POST("/mkdir/test/").
		Expect().Status(http.StatusOK).
		Body().IsEqual("OK")

	data := []byte{1, 2, 3, 4}

	auth.POST("/upload/test/file.jpg").
		WithHeader("Content-Length", strconv.Itoa(len(data))).
		WithMultipart().
		WithFileBytes("file", "file.dat", data).
		Expect().Status(http.StatusOK)

	e.GET("/download/test/file.jpg").Expect().Status(http.StatusOK).
		HasContentType("image/jpeg").Body().Length().IsEqual(len(data))
	auth.POST("/upload/test/file.jpg").
		WithQuery("comment", "this is comment").
		WithQuery("expire", "1second").
		WithHeader("Content-Length", strconv.Itoa(len(data))).
		WithMultipart().
		WithFileBytes("file", "file.dat", data).
		Expect().Status(http.StatusOK)

	auth.POST("/remove/test/file.jpg").Expect().Status(http.StatusOK)

	auth.POST("/upload/test/file2.jpg").
		WithQuery("comment", "this is comment").
		WithQuery("expire", "1second").
		WithHeader("Content-Length", strconv.Itoa(len(data))).
		WithMultipart().
		WithFileBytes("file", "file.dat", data).
		Expect().Status(http.StatusOK)

	// sleep for 1,5second and wait for expire previous uploaded file
	time.Sleep(time.Millisecond * 1500)

	e.GET("/download/test/file2.jpg").Expect().Status(http.StatusNotFound)

}
