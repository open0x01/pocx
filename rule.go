package pocx

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/antchfx/htmlquery"
	"github.com/google/cel-go/cel"
	lru "github.com/hashicorp/golang-lru"
	"github.com/iami317/pocx/expression"
	"github.com/iami317/pocx/pocbase"
	"github.com/iami317/shttp"
	"github.com/zmap/zgrab2/lib/ssh"
	"gopkg.in/yaml.v3"
	"io"
	"io/ioutil"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	_ctxHTTPClient = "_http_client"
	_ctxNetClient  = "_net_client"
	_ctxNetConn    = "_net_conn"
	_ctxSshConfig  = "_ssh_config"
)
const (
	netInputHexType  = "hex"
	netInputTextType = "text"
)

var titleRegexp = regexp.MustCompile(`(?is)<title>(.*?)</title>`)

//‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾
// YamlRule struct
//_______________________________________________________________________

type YamlRule struct {
	Request    interface{} `yaml:"request"`
	Expression string      `yaml:"expression"`
	Output     yaml.Node   `yaml:"output"`

	expProgram     cel.Program   `yaml:"-"`
	outputPrograms []*setProgram `yaml:"-"`
}

func (yr *YamlRule) Check(ctx context.Context, in interface{}, celVars map[string]interface{}, snapShot *pocbase.SnapShot) (bool, error) {
	var response interface{}
	switch subRule := yr.Request.(type) {
	case *httpRule:
		sreq := in.(*shttp.Request)
		resp, body, localAddr, err := subRule.Do(ctx, sreq, celVars)
		if localAddr != nil {
			snapShot.SrcIp = localAddr.IP.String()
			snapShot.SrcPort = localAddr.Port
			var u []string
			if strings.Contains(sreq.RawRequest.URL.Host, "]:") {
				u = strings.Split(strings.TrimLeft(sreq.RawRequest.URL.Host, "["), "]:")
			} else if strings.Contains(sreq.RawRequest.URL.Host, ":") {
				u = strings.Split(sreq.RawRequest.URL.Host, ":")
			}
			if len(u) >= 2 {
				p, _ := strconv.Atoi(u[1])
				snapShot.DstIp = u[0]
				snapShot.DstPort = p
			}

		}

		if err != nil {
			return false, err
		}

		requestTmp, _ := sreq.GetRaw()
		responseTmp, _ := resp.GetRaw()
		snapShot.Content = append(snapShot.Content, pocbase.SnapShotContent{
			Request:     sreq,
			RequestRaw:  requestTmp,
			Response:    resp,
			ResponseRaw: responseTmp,
		})
		u := resp.GetUrl()
		headers := make(map[string]string)
		for k, vv := range resp.GetHeaders() {
			if len(vv) > 0 {
				for _, vvv := range vv {
					headers[k] += vvv + "; "
				}
			}
		}
		var cert []byte
		if resp.RawResponse.TLS != nil && len(resp.RawResponse.TLS.PeerCertificates) > 0 {
			cert = resp.RawResponse.TLS.PeerCertificates[0].Raw
		}
		var rawHeader bytes.Buffer
		_ = resp.RawResponse.Header.WriteSubset(&rawHeader, make(map[string]bool))
		titleMatches := titleRegexp.FindSubmatch(body)
		var title string
		if len(titleMatches) == 2 {
			title = string(titleMatches[1])
		}
		latency, err := resp.GetLatency()
		if err != nil {
			return false, err
		}
		response = &expression.HTTPResponseType{
			Url: &expression.UrlType{
				Scheme:   u.Scheme,
				Domain:   u.Host,
				Host:     u.Hostname(),
				Port:     u.Port(),
				Path:     u.Path,
				Query:    u.Query().Encode(),
				Fragment: u.Fragment,
			},
			Status:      int32(resp.GetStatus()),
			Body:        body,
			BodyString:  string(body),
			Headers:     headers,
			ContentType: resp.GetContentType(),
			Title:       title,
			TitleString: title,
			RawHeader:   rawHeader.Bytes(),
			RawCert:     cert,
			Latency:     int32(latency.Milliseconds()),
			// todo: latency 和 raw真的需要么
			Raw: responseTmp,
		}
		celVars["response"] = response
	case *networkRule:
		resp, err := subRule.Do(ctx, celVars)
		if err != nil {
			return false, err
		}
		conn := ctx.Value(_ctxNetConn).(net.Conn)
		response = &expression.NetworkResponseType{
			Conn: &expression.ConnType{
				Source:      netAddr2ExprAddr(conn.LocalAddr()),
				Destination: netAddr2ExprAddr(conn.RemoteAddr()),
			},
			Raw: resp,
		}
		celVars["response"] = response
	case *sshRule:
		sreq := in.(*pocbase.ServiceAsset)
		sshConfig := ctx.Value(_ctxSshConfig).(*ssh.ClientConfig)
		data := new(ssh.HandshakeLog)
		sshConfig.ConnLog = data
		sshConfig.DontAuthenticate = true
		sshConfig.Timeout = time.Duration(subRule.ReadTimeout) * time.Second
		sshConfig.BannerCallback = func(banner string) error {
			data.Banner = strings.TrimSpace(banner)
			return nil
		}

		client, err := ssh.Dial("tcp", sreq.Address(), sshConfig)
		if err != nil {
			return false, err
		}
		defer client.Close()
		dataBy, err := json.Marshal(sshConfig.ConnLog)
		if err != nil {
			return false, err
		}
		response = &expression.SshResponseType{
			Conn: &expression.ConnType{
				Source:      netAddr2ExprAddr(client.LocalAddr()),
				Destination: netAddr2ExprAddr(client.RemoteAddr()),
			},
			Raw: dataBy,
		}
		celVars["response"] = response

	default:
		return false, fmt.Errorf("unknown request rule")
	}

	result, _, err := yr.expProgram.Eval(celVars)
	if err != nil {
		return false, err
	}
	// extract var from output
	for _, item := range yr.outputPrograms {
		result, _, err := item.pg.Eval(celVars)
		if err != nil {
			return false, err
		}
		celVars[item.key] = result.Value()
	}
	if !result.Value().(bool) {
		return false, nil
	}
	return true, nil
}

//‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾
// httpRule struct
//_______________________________________________________________________

type httpRule struct {
	Cache           bool              `yaml:"cache"`
	Method          string            `yaml:"method"`
	Path            string            `yaml:"path"`
	Headers         map[string]string `yaml:"headers"`
	Body            string            `yaml:"body"`
	FollowRedirects *bool             `yaml:"follow_redirects"`
}

// todo: don't be a global variable
var reqCache, _ = lru.NewARC(100)

func (r *httpRule) Do(ctx context.Context, req *shttp.Request, celVars map[string]interface{}) (*shttp.Response, []byte, *net.TCPAddr, error) {
	ctxClient := ctx.Value(_ctxHTTPClient).(*shttp.Client)
	client, _ := shttp.NewClient(ctxClient.ClientOptions, nil)
	defer client.HTTPClient.CloseIdleConnections()
	if r.FollowRedirects != nil && *r.FollowRedirects {
		client = client.WithRedirect(true)
	}
	newReq, err := r.replaceReq(req, celVars)
	if err != nil {
		return nil, nil, nil, err
	}
	var resp *shttp.Response
	// 只考虑 get 方法, 其他请求可能不是幂等的
	r.Cache = false
	if newReq.GetMethod() == http.MethodGet && r.Cache {
		var builder strings.Builder
		builder.WriteString(newReq.GetUrl().String())
		for k, vv := range newReq.GetHeaders() {
			builder.WriteString(k + "##" + strings.Join(vv, ","))
		}
		key := builder.String()
		respInter, exist := reqCache.Get(key)
		if exist {
			// a shadow copy
			respCopy, ok := respInter.(*shttp.Response)
			if !ok {
				// 一定是 error 类型
				return nil, nil, nil, respInter.(error)
			}
			resp = respCopy
		} else {
			resp, err = client.Do(ctx, newReq)
			if err != nil {
				reqCache.Add(key, err)
				return nil, nil, nil, err
			}
			if r.FollowRedirects != nil && *r.FollowRedirects {
				resp, _, _, err = r.processRedirect(ctx, client, resp, req, 0)
			}
			reqCache.Add(key, resp)
		}
	} else {
		resp, err = client.Do(ctx, newReq)
		if err != nil {
			// 处理返回超时
			//if strings.Contains(err.Error(), "net/http: timeout awaiting response headers") {
			//	respErr := &shttp.Response{Body: []byte("timeout awaiting response headers"), RawResponse: &http.Response{Request: newReq.RawRequest}}
			//	return respErr, respErr.GetBody(), nil
			//}
			return nil, nil, client.LocalAddress, err
		}
	}

	// 处理网页重定向
	if r.FollowRedirects != nil && *r.FollowRedirects {
		return r.processRedirect(ctx, client, resp, req, 0)
	}
	return resp, resp.GetBody(), client.LocalAddress, nil
}

func (r *httpRule) processRedirect(ctx context.Context, client *shttp.Client, resp *shttp.Response, req *shttp.Request, num int) (*shttp.Response, []byte, *net.TCPAddr, error) {
	// 最大跳转次数
	if num > client.ClientOptions.MaxRedirect {
		return resp, resp.GetBody(), client.LocalAddress, nil
	}
	doc, err1 := htmlquery.Parse(strings.NewReader(string(resp.Body)))
	if err1 != nil || doc == nil {
		return resp, resp.GetBody(), client.LocalAddress, nil
	}
	node := htmlquery.FindOne(doc, `//meta[@http-equiv="refresh" and @content]/@content`)
	// 无重定向则直接返回
	if node == nil {
		return resp, resp.GetBody(), client.LocalAddress, nil
	}
	// reg1, _ := regexp.Compile(`'[^# ]*'`)
	reg1, _ := regexp.Compile(`=[^# ]*`)
	if err1 != nil {
		return resp, resp.GetBody(), client.LocalAddress, nil
	}
	redirectsUrl := reg1.FindString(node.FirstChild.Data)
	if redirectsUrl == "" {
		return resp, resp.GetBody(), client.LocalAddress, nil
	} else {
		redirectsUrl = strings.ReplaceAll(redirectsUrl, `'`, "")
		redirectsUrl = strings.ReplaceAll(redirectsUrl, `=`, "")
		redirectsUrl = strings.ReplaceAll(redirectsUrl, `/`, "")
	}
	hr, err1 := http.NewRequest(shttp.MethodGet, req.RawRequest.URL.String(), nil)
	if err1 != nil {
		return resp, resp.GetBody(), client.LocalAddress, nil
	}
	req1 := &shttp.Request{
		RawRequest: hr,
	}
	req1.RawRequest.URL.Path = `/` + redirectsUrl
	resp1, err := client.Do(ctx, req1)
	if err != nil {
		return nil, nil, client.LocalAddress, err
	}
	// 递归
	return r.processRedirect(ctx, client, resp1, req1, num+1)
}

func (r *httpRule) replaceUri(u *url.URL, requestURI string) (*url.URL, error) {
	if requestURI == "" {
		requestURI = "/"
	}
	newURI, err := url.ParseRequestURI(requestURI)
	if err != nil {
		if strings.Contains(err.Error(), `invalid URL escape`) {
			newURL := *u
			newURL.Opaque = requestURI
			return &newURL, nil
		}
		return nil, err
	}

	newURL := *u
	newURL.Path = newURI.Path
	newURL.RawPath = newURI.RawPath
	newURL.RawQuery = newURI.RawQuery
	newURL.Fragment = newURI.Fragment
	return &newURL, nil
}

func (r *httpRule) replaceReq(req *shttp.Request, celVars map[string]interface{}) (*shttp.Request, error) {
	// 如果用户没有指定path，就用原请求中的path
	newPath := req.GetPath()
	if r.Path != "" {
		dir, _ := path.Split(newPath)
		newPath = strings.TrimRight(dir, "/") + renderVariables(r.Path, celVars)
	}

	newURL, err := r.replaceUri(req.RawRequest.URL, newPath)
	if err != nil {
		return nil, err
	}
	req.RawRequest.URL = newURL

	// 如果没有指定Method，就用原请求的method
	if r.Method != "" {
		req.RawRequest.Method = r.Method
	}

	var isMultipart bool
	var boundary string
	for k, v := range r.Headers {
		if strings.EqualFold(k, "content-type") && strings.Contains(v, "boundary") {
			isMultipart = true
			_, params, err := mime.ParseMediaType(v)
			if err != nil {
				return nil, err
			}
			boundary = params["boundary"]
		}
		req = req.SetHeader(k, renderVariables(v, celVars))
	}

	if r.Body != "" {
		bodyStr := renderVariables(r.Body, celVars)
		if isMultipart {
			body, err := FixMultipartBody(bodyStr, boundary)
			if err != nil {
				return nil, err
			}
			req = req.SetBody(body)
		} else {
			req = req.SetBody([]byte(bodyStr))
		}
	}
	return req, nil
}

var variableRegex = regexp.MustCompile(`{{([a-zA-Z0-9_]+)}}`)

func renderVariables(template string, variables map[string]interface{}) string {
	if !strings.Contains(template, "{{") || len(variables) == 0 {
		return template
	}
	for _, arr := range variableRegex.FindAllStringSubmatch(template, -1) {
		if val, ok := variables[arr[1]]; ok {
			switch v := val.(type) {
			// 对 bytes 做特殊处理，因为直接 %v 输出不对
			case []byte, byte:
				template = strings.ReplaceAll(template, arr[0], fmt.Sprintf("%s", v))
			default:
				template = strings.ReplaceAll(template, arr[0], fmt.Sprintf("%v", v))
			}
		}
	}
	return template
}

func FixMultipartBody(dirtyBody string, boundary string) ([]byte, error) {
	mr := multipart.NewReader(strings.NewReader(dirtyBody), boundary)
	var tmp []struct {
		data   []byte
		header textproto.MIMEHeader
	}
	for {
		part, err := mr.NextPart()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		data, err := ioutil.ReadAll(part)
		if err != nil {
			return nil, err
		}
		tmp = append(tmp, struct {
			data   []byte
			header textproto.MIMEHeader
		}{data, part.Header})
	}

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	mw.SetBoundary(boundary)
	for _, pair := range tmp {
		part, err := mw.CreatePart(pair.header)
		if err != nil {
			return nil, err
		}
		// write will success
		_, _ = part.Write(pair.data)
	}
	if err := mw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

//‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾
// networkRule struct
//_______________________________________________________________________

type NetInput struct {
	Data string `yaml:"data"`
	Type string `yaml:"type"`
}

type networkRule struct {
	Inputs      []*NetInput `yaml:"inputs"`
	ReadTimeout int         `yaml:"read_timeout"`
	raw         []byte

	// todo: 暂未实现
	Cache        bool `yaml:"cache"`
	ConnectionId int  `yaml:"connection_id"`
}

func (r *networkRule) Do(ctx context.Context, celVars map[string]interface{}) ([]byte, error) {
	conn := ctx.Value(_ctxNetConn).(net.Conn)
	fixInput, err := r.replaceInputs(celVars)
	if err != nil {
		return nil, err
	}
	if r.ReadTimeout != 0 {
		err = conn.SetReadDeadline(time.Now().Add(time.Duration(r.ReadTimeout) * time.Second))
		if err != nil {
			return nil, err
		}
	}
	if len(fixInput) != 0 {
		_, err = conn.Write(fixInput)
		if err != nil {
			return nil, err
		}
	}
	// todo: make config and use sync.pool
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func (r *networkRule) replaceInputs(celVars map[string]interface{}) ([]byte, error) {
	var buffer bytes.Buffer
	for _, input := range r.Inputs {
		// 默认值 text
		if input.Type == "" {
			input.Type = netInputTextType
		}
		switch input.Type {
		case netInputHexType:
			byteData, err := hex.DecodeString(input.Data)
			if err != nil {
				return nil, err
			}
			buffer.Write(byteData)
		case netInputTextType:
			fixRaw := renderVariables(input.Data, celVars)
			buffer.WriteString(fixRaw)
		default:
			return nil, fmt.Errorf("unknown network input type")
		}
	}
	return buffer.Bytes(), nil
}

func netAddr2ExprAddr(addr net.Addr) *expression.AddrType {
	host, port, _ := net.SplitHostPort(addr.String())
	return &expression.AddrType{
		Transport: addr.Network(),
		Addr:      host,
		Port:      port,
	}
}

type sshRule struct {
	ReadTimeout int    `yaml:"read_timeout"`
	User        string `yaml:"user"`
}
