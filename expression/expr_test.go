package expression

import (
	"context"
	"fmt"
	"github.com/iami317/hubur"
	"github.com/open0x01/reverkit"
	"github.com/stretchr/testify/require"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

func TestExprHTTPRequest(t *testing.T) {
	assert := require.New(t)
	req := HTTPRequestType{
		Url: &UrlType{
			Scheme:   "https",
			Domain:   "www.test.com",
			Host:     "www.test.com:8080",
			Port:     "8080",
			Path:     "abc",
			Query:    "a=1&b=2",
			Fragment: "fg",
		},
		Method: "GET",
		Headers: map[string]string{
			"Cred": "admin123",
		},
		ContentType: "utf-8",
		Body:        []byte("hello"),
		Raw:         []byte("GET / HTTP/1.0\r\n\r\n"),
	}
	toChecked := `
request.url.scheme == "https" && 
request.url.domain == "www.test.com" && 
request.url.host == "www.test.com:8080" && 
request.url.port == "8080" && 
request.url.path == "abc" &&
request.url.query == "a=1&b=2" &&
request.url.fragment == "fg" &&
request.method == "GET" && 
request.headers["Cred"] == "admin123" &&
request.content_type == "utf-8" && 
request.body == bytes("hello") &&
request.raw == bytes("GET / HTTP/1.0\r\n\r\n")
`
	env, err := NewCELBuilder().WithHTTPType().Build()
	assert.Nil(err)
	result, err := Evaluate(env, toChecked, map[string]interface{}{
		"request": &req,
	})
	assert.Nil(err)
	assert.True(result.Value().(bool))

	result, err = Evaluate(env, `request.url.scheme == "http"`, map[string]interface{}{
		"request": &req,
	})
	assert.Nil(err)
	assert.False(result.Value().(bool))
}

func TestExprHTTPResponse(t *testing.T) {
	assert := require.New(t)
	resp := HTTPResponseType{
		Url: &UrlType{
			Scheme:   "https",
			Domain:   "www.test.com",
			Host:     "www.test.com:8080",
			Port:     "8080",
			Path:     "abc",
			Query:    "a=1&b=2",
			Fragment: "fg",
		},
		Status: 200,
		Body:   []byte("hello"),
		Headers: map[string]string{
			"Cred": "admin123",
		},
		ContentType: "utf-8",
		Latency:     10,
		Raw:         []byte("GET / HTTP/1.0\r\n\r\n"),
	}
	toChecked := `
response.url.scheme == "https" && 
response.url.domain == "www.test.com" && 
response.url.host == "www.test.com:8080" && 
response.url.port == "8080" && 
response.url.path == "abc" &&
response.url.query == "a=1&b=2" &&
response.url.fragment == "fg" &&
response.headers["Cred"] == "admin123" &&
"Cred" in response.headers && 
response.content_type == "utf-8" && 
response.body == bytes("hello") &&
response.raw == bytes("GET / HTTP/1.0\r\n\r\n") && 
response.status == 200 && 
response.latency == 10
`
	env, err := NewCELBuilder().WithHTTPType().Build()
	assert.Nil(err)
	result, err := Evaluate(env, toChecked, map[string]interface{}{
		"response": &resp,
	})
	assert.Nil(err)
	assert.True(result.Value().(bool))

	result, err = Evaluate(env, `response.url.scheme == "http"`, map[string]interface{}{
		"response": &resp,
	})
	assert.Nil(err)
	assert.False(result.Value().(bool))
}

func TestExprTCPAndUDP(t *testing.T) {
	assert := require.New(t)
	toChecked := `
request.raw == bytes("abc") && 
response.raw == bytes("def") && 
response.conn.source.transport == "fake-trans" &&
response.conn.source.addr == "192.168.1.1" && 
response.conn.source.port == "8080" && 
response.conn.destination.transport == "fake-trans-2" &&
response.conn.destination.addr == "192.168.1.2" &&
response.conn.destination.port == "9090" 
`
	env, err := NewCELBuilder().WithNetworkType().Build()
	assert.Nil(err)
	result, err := Evaluate(env, toChecked, map[string]interface{}{
		"request": &NetworkRequestType{
			Raw: []byte("abc"),
		},
		"response": &NetworkResponseType{
			Conn: &ConnType{
				Source: &AddrType{
					Transport: "fake-trans",
					Addr:      "192.168.1.1",
					Port:      "8080",
				},
				Destination: &AddrType{
					Transport: "fake-trans-2",
					Addr:      "192.168.1.2",
					Port:      "9090",
				},
			},
			Raw: []byte("def"),
		},
	})
	assert.Nil(err)
	assert.True(result.Value().(bool))
	//
	//env, err = NewCELBuilder().WithNetworkType().Build()
	//assert.Nil(err)
	//result, err = Evaluate(env, toChecked, map[string]interface{}{
	//	"request": &UDPRequestType{
	//		Data:           []byte("abc"),
	//	},
	//	"response": &UDPResponseType{
	//		Conn: &ConnType{
	//			Source: &AddrType{
	//				Transport:     "fake-trans",
	//				Addr:          "192.168.1.1",
	//				Port:          "8080",
	//			},
	//			Destination: &AddrType{
	//				Transport:     "fake-trans-2",
	//				Addr:          "192.168.1.2",
	//				Port:          "9090",
	//			},
	//		},
	//		Data: []byte("def"),
	//	},
	//})
	//assert.Nil(err)
	//assert.True(result.Value().(bool))
}

func TestExprFunctions(t *testing.T) {
	assert := require.New(t)
	env, err := NewCELBuilder().Build()
	assert.Nil(err)
	value, err := Evaluate(env, `"abc".icontains("Ab")`, map[string]interface{}{})
	assert.Nil(err)
	assert.True(value.Value().(bool))

	value, err = Evaluate(env, `substr("admin123", 0, 3)`, map[string]interface{}{})
	assert.Nil(err)
	assert.True(value.Value().(string) == "adm")

	value, err = Evaluate(env, `replaceAll("admin123admin123admin", "123", "456")`, map[string]interface{}{})
	assert.Nil(err)
	assert.True(value.Value().(string) == "admin456admin456admin")

	value, err = Evaluate(env, `printable("456")`, map[string]interface{}{})
	assert.Nil(err)
	assert.True(value.Value().(string) == "456")

	value, err = Evaluate(env, `b"abc".bcontains(b"ab")`, map[string]interface{}{})
	assert.Nil(err)
	assert.True(value.Value().(bool))

	value, err = Evaluate(env, `"a.c".bmatches(b"abc")`, map[string]interface{}{})
	assert.Nil(err)
	assert.True(value.Value().(bool))

	value, err = Evaluate(env, `"ad(?<num>\\d+)ok".submatch("ad242342ok")`, map[string]interface{}{})
	assert.Nil(err)
	assert.Equal(value.Value(), map[string]string{
		"0":   "ad242342ok",
		"num": "242342",
	})

	value, err = Evaluate(env, `md5("admin")`, map[string]interface{}{})
	assert.Nil(err)
	assert.Equal(value.Value(), "21232f297a57a5a743894a0e4a801fc3")

	value, err = Evaluate(env, `base64("admin") == base64(b"admin") && base64("admin") == "YWRtaW4="`, map[string]interface{}{})
	assert.Nil(err)
	assert.True(value.Value().(bool))

	value, err = Evaluate(env, `base64Decode("YWRtaW4=") == base64Decode(b"YWRtaW4=") && base64Decode("YWRtaW4=") == "admin"`, map[string]interface{}{})
	assert.Nil(err)
	assert.True(value.Value().(bool))

	value, err = Evaluate(env, `urlencode("/a?c=d") == urlencode("/a?c=d") && urlencode("/a?c=d") == "%2Fa%3Fc%3Dd"`, map[string]interface{}{})
	assert.Nil(err)
	assert.True(value.Value().(bool))

	value, err = Evaluate(env, `urldecode("%2Fa%3Fc%3Dd") == urldecode("%2Fa%3Fc%3Dd") && urldecode("%2Fa%3Fc%3Dd") == "/a?c=d"`, map[string]interface{}{})
	assert.Nil(err)
	assert.True(value.Value().(bool))

	value, err = Evaluate(env, `randomInt(8, 9)`, map[string]interface{}{})
	assert.Nil(err)
	assert.Equal(value.Value(), int64(8))

	value, err = Evaluate(env, `randomLowercase(8)`, map[string]interface{}{})
	assert.Nil(err)
	assert.Equal(len(value.Value().(string)), 8)

	start := time.Now()
	value, err = Evaluate(env, `sleep(1)`, map[string]interface{}{})
	assert.Nil(err)
	assert.True(time.Since(start).Milliseconds() > 1000)
}

func TestMapNoSuchKey(t *testing.T) {
	assert := require.New(t)
	env, err := NewCELBuilder().WithHTTPType().Build()
	assert.Nil(err)
	exprString := `response.headers["Exist"] == "Not"`
	ast, iss := env.Compile(exprString)
	assert.Nil(iss)
	prg, err := env.Program(ast)
	assert.Nil(err)
	out, _, err := prg.Eval(map[string]interface{}{
		"response": &HTTPResponseType{
			Headers: map[string]string{},
		},
	})
	assert.Nil(err)
	assert.False(out.Value().(bool))
}

func TestReverseType(t *testing.T) {
	assert := require.New(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dbPath, err := hubur.GetTempFilePath()
	assert.Nil(err)
	defer os.RemoveAll(dbPath)
	server, client, err := reverkit.NewLocalTestServer(ctx, dbPath)
	assert.Nil(err)
	defer server.Close()

	env, err := NewCELBuilder().WithReverseType(client).Build()
	assert.Nil(err)
	value, err := Evaluate(env, `newReverse()`, map[string]interface{}{})
	assert.Nil(err)
	realValue := value.Value().(*ReverseType)
	u := realValue.Url
	assert.Equal("http", u.Scheme)
	serverConf := server.Config().HTTPServerConfig
	assert.Equal(net.JoinHostPort(serverConf.ListenIP, serverConf.ListenPort), u.Host)
	assert.Equal(serverConf.ListenIP, u.Domain)
	assert.Equal(serverConf.ListenPort, u.Port)
	assert.NotEmpty(u.Path)

	env, err = NewCELBuilder().WithReverseType(client).Build()
	assert.Nil(err)
	value, err = Evaluate(env, `newReverse().url`, map[string]interface{}{})
	assert.Nil(err)
	vs := fmt.Sprintf("%s", value.Value())
	assert.True(strings.HasPrefix(vs, "http://"))

	env, err = NewCELBuilder().WithReverseType(client).Build()
	assert.Nil(err)
	value, err = Evaluate(env, `newReverse().rmi`, map[string]interface{}{})
	assert.Nil(err)
	vs = fmt.Sprintf("%s", value.Value())
	assert.True(strings.HasPrefix(vs, "rmi://"))

	// reverse_wait
	env, err = NewCELBuilder().WithReverseType(client).Build()
	assert.Nil(err)
	start := time.Now()
	value, err = Evaluate(env, `newReverse().wait(1)`, map[string]interface{}{})
	assert.Nil(err)
	assert.False(value.Value().(bool))
	assert.True(time.Since(start).Milliseconds() > 1000)
}
