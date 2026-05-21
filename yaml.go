package pocx

import (
	"context"
	"fmt"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/interpreter/functions"
	"github.com/iami317/pocx/expression"
	"github.com/iami317/pocx/pocbase"
	"github.com/zan8in/oobadapter/pkg/oobadapter"
	expr "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
	"gopkg.in/yaml.v3"
	"strconv"
	"strings"
	"time"
)

type YamlFingerprint = pocbase.Fingerprint
type YamlVulnerability struct {
	VulId       []string          `yaml:"vul_id" #:"漏洞编号"`
	VulType     string            `yaml:"vul_type" #:"漏洞类型"`
	Author      string            `yaml:"author" #:"作者"`
	Description string            `yaml:"description" #:"漏洞描述"`
	Severity    string            `yaml:"severity" #:"漏洞级别"`
	Score       float64           `yaml:"score" #:"评分"`
	Harm        string            `yaml:"harm" #:"漏洞危害"`
	Links       []string          `yaml:"links" #:"链接"`
	Proof       map[string]string `yaml:"proof"`
}

type YamlPoc struct {
	Id        string               `yaml:"id" #:"id 信息"`
	Name      string               `yaml:"name" #:"插件名称"`
	Tags      []string             `yaml:"tags"`
	Transport string               `yaml:"transport" #:"协议类型， http/tcp/udp"`
	Set       yaml.Node            `yaml:"set" #:"自定义变量"`
	Rules     map[string]*YamlRule `yaml:"rules" #:"请求列表"`
	Pattern   string               `yaml:"expression" #:"请求控制"`
	Detail    struct {
		Fingerprint   YamlFingerprint   `yaml:"fingerprint"`
		Vulnerability YamlVulnerability `yaml:"vulnerability"`
	} `yaml:"detail" #:"插件细节"`

	NeedReverse bool
	setPrograms []*setProgram `yaml:"-"`
	config      *Config
}

func (poc *YamlPoc) Init(ctx context.Context) error {
	config, err := ContextConfig(ctx)
	if err != nil {
		return err
	}
	poc.config = config
	//if poc.NeedReverse && poc.config.ReverClient == nil {
	//	return fmt.Errorf("reverse ip need to be configured")
	//}

	varContext, err := poc.compileVariables()
	if err != nil {
		return fmt.Errorf("id:%v-name:%v-err:%v", poc.Id, poc.Name, err)
	}
	if err = poc.compileExpression(varContext); err != nil {
		return fmt.Errorf("id:%v-name:%v-err:%v", poc.Id, poc.Name, err)
	}
	return nil
}

func (poc *YamlPoc) Close() {
	return
}

func (poc *YamlPoc) Meta() *pocbase.MetaInfo {
	return &pocbase.MetaInfo{
		Plugin: &pocbase.PluginInfo{
			ID:   poc.Id,
			Name: poc.Name,
		},
	}
}

func (poc *YamlPoc) Match(ctx context.Context, in []string) bool {
	if len(in) == 0 || len(poc.Tags) == 0 {
		return false
	} else {
		if len(in) > 0 {
			for _, v := range in {
				for _, y := range poc.Tags {
					if strings.Contains(strings.ToLower(v), strings.ToLower(y)) {
						return true
					}
					if strings.Contains(strings.ToLower(y), strings.ToLower(v)) {
						return true
					}
					for _, i2 := range strings.Split(v, " ") {
						if len(i2) > 0 {
							if strings.Contains(strings.ToLower(v), strings.ToLower(y)) {
								return true
							}
							if strings.Contains(strings.ToLower(y), strings.ToLower(v)) {
								return true
							}
						}
					}
				}
			}
		}
		return false
	}
}

func (poc *YamlPoc) Scan(ctx context.Context, in interface{}) (pocbase.SnapShot, pocbase.Event, error) {
	var snapShot pocbase.SnapShot
	var err error
	var result bool
	srv, isService := in.(*pocbase.ServiceAsset)
	requestAsset, isHTTP := in.(*pocbase.RequestAsset)
	if poc.Transport == pocbase.TransportHTTP && isService {
		return snapShot, nil, nil
	}
	if (poc.Transport == pocbase.TransportTCP || poc.Transport == pocbase.TransportUDP || poc.Transport == pocbase.TransportSSH) && isHTTP {
		return snapShot, nil, nil
	}
	env := expression.NewCELBuilder()
	celVars := make(map[string]interface{})
	// ctx 预处理
	switch poc.Transport {
	case pocbase.TransportHTTP:
		rawRequest := requestAsset.Req
		ctx = context.WithValue(ctx, _ctxHTTPClient, poc.config.HttpClient)
		header := make(map[string]string)
		for k := range rawRequest.GetHeaders() {
			header[k] = rawRequest.RawRequest.Header.Get(k)
		}
		celVars["request"] = &expression.HTTPRequestType{
			Url: &expression.UrlType{
				Scheme:   rawRequest.GetScheme(),
				Domain:   rawRequest.GetHost(),
				Host:     rawRequest.GetHostName(),
				Port:     rawRequest.GetPort(),
				Path:     rawRequest.GetPath(),
				Query:    rawRequest.GetQuery(),
				Fragment: rawRequest.GetFragment(),
			},
			Method:      rawRequest.GetMethod(),
			Headers:     header,
			ContentType: rawRequest.GetContentType(),
			// todo: body and raw
			//Body:        body,
			//Raw:         nil,
		}

	case pocbase.TransportTCP, pocbase.TransportUDP:
		ctx = context.WithValue(ctx, _ctxNetClient, poc.config.NetClient)
		conn, err := poc.config.NetClient.Dial(ctx, srv)
		if err != nil {
			return snapShot, nil, err
		}
		ctx = context.WithValue(ctx, _ctxNetClient, poc.config.NetClient)
		ctx = context.WithValue(ctx, _ctxNetConn, conn)
		celVars["request"] = &expression.NetworkResponseType{
			Conn: &expression.ConnType{
				Source:      netAddr2ExprAddr(conn.LocalAddr()),
				Destination: netAddr2ExprAddr(conn.RemoteAddr()),
			},
			Raw: nil,
		}

	case pocbase.TransportSSH: //todo:需要配置的参数暂时没有
		ctx = context.WithValue(ctx, _ctxSshConfig, poc.config.SshConfig)
		//rawRequest := requestAsset.Req

	default:
		return snapShot, nil, fmt.Errorf("unsupported transport %s", poc.Transport)
	}

	for _, prg := range poc.setPrograms {
		val, _, err := prg.pg.Eval(celVars)
		if err != nil {
			return snapShot, nil, err
		}
		celVars[prg.key] = val.Value()
	}

	for key, rule := range poc.Rules {
		fnId := fmt.Sprintf("%s_void", key)
		env.AddDeclarations(decls.NewFunction(key, decls.NewOverload(fnId, []*expr.Type{}, decls.Bool)))
		rule := rule
		var enter interface{}
		switch poc.Transport {
		case pocbase.TransportHTTP:
			enter = requestAsset.Req.Clone()
		case pocbase.TransportTCP, pocbase.TransportUDP, pocbase.TransportSSH:
			enter = srv.Clone()
		}

		env.AddProgramOptions(cel.Functions(&functions.Overload{
			Operator: fnId,
			Function: func(values ...ref.Val) ref.Val {
				if len(values) != 0 {
					return types.NewErr("arguments error")
				}
				result, err = rule.Check(ctx, enter, celVars, &snapShot)
				if err != nil {
					return types.NewErr(err.Error())
				}
				return types.Bool(result)
			},
		}))
	}

	prg, err := env.BuildAndCompile(poc.Pattern, true)
	if err != nil {
		return snapShot, nil, fmt.Errorf("compile pattern error %v", err)
	}
	val, _, err := prg.Eval(map[string]interface{}{})
	//val, detail, err := prg.Eval(map[string]interface{}{})
	_ = make(map[string]interface{})
	if err != nil {
		return snapShot, nil, err
	}
	if val.Value().(bool) {
		if poc.Detail.Fingerprint.IsEmpty() {
			event, err := poc.getVulResult(in, celVars, snapShot)
			return snapShot, event, err
		} else {
			event, err := poc.getFingerResult(in, celVars, snapShot)
			return snapShot, event, err
		}
	} else {
		return snapShot, nil, fmt.Errorf("match nil")
	}
}

func (poc *YamlPoc) getVulResult(in interface{}, vars map[string]interface{}, snapShot pocbase.SnapShot) (pocbase.Event, error) {
	var target *pocbase.TargetInfo
	var detail *pocbase.VulDetail

	extractedInfo := make(map[string]interface{})
	for k, v := range vars {
		if k == "request" || k == "response" {
			continue
		}
		if _, ok := v.(*expression.ReverseType); ok {
			continue
		}
		extractedInfo[k] = v
	}

	extractedInfo["vul_id"] = poc.Detail.Vulnerability.VulId
	extractedInfo["vul_type"] = poc.Detail.Vulnerability.VulType
	extractedInfo["description"] = poc.Detail.Vulnerability.Description
	extractedInfo["severity"] = poc.Detail.Vulnerability.Severity
	extractedInfo["score"] = poc.Detail.Vulnerability.Score
	extractedInfo["harm"] = poc.Detail.Vulnerability.Harm
	for k, v := range poc.Detail.Vulnerability.Proof {
		extractedInfo[k] = renderVariables(v, vars)
	}

	switch poc.Transport {
	case pocbase.TransportHTTP:
		req := in.(*pocbase.RequestAsset).Req
		host := req.GetHostName()
		port := req.GetPort()
		var p int
		p, _ = strconv.Atoi(port)
		if p == 0 {
			if req.GetScheme() == "https" {
				p = 443
			} else {
				p = 80
			}
		}
		target = &pocbase.TargetInfo{
			Host: host,
			Path: req.GetPath(),
			Port: p,
		}
		detail = &pocbase.VulDetail{
			Payload:       "",
			SnapShot:      snapShot.Content,
			ExtractedInfo: extractedInfo,
		}

	case pocbase.TransportTCP, pocbase.TransportUDP, pocbase.TransportSSH:
		asset := in.(*pocbase.ServiceAsset)
		target = &pocbase.TargetInfo{
			Host: asset.Host,
			Path: "",
			Port: asset.Port,
		}
		// todo: snapshot
		detail = &pocbase.VulDetail{
			Payload:       "",
			SnapShot:      nil,
			ExtractedInfo: extractedInfo,
		}
	}

	pluginInfo := &pocbase.PluginInfo{
		ID:   poc.Id,
		Name: poc.Name,
	}

	resultEvent := &pocbase.VulEvent{
		Timestamp: time.Now(),
		Plugin:    pluginInfo,
		Details:   detail,
		Target:    target,
	}

	return resultEvent, nil
}

func (poc *YamlPoc) getFingerResult(in interface{}, vars map[string]interface{}, snapShot pocbase.SnapShot) (pocbase.Event, error) {
	var target *pocbase.TargetInfo
	switch poc.Transport {
	case pocbase.TransportHTTP:
		req := in.(*pocbase.RequestAsset).Req
		host := req.GetHostName()
		port := req.GetPort()
		var p int
		p, _ = strconv.Atoi(port)
		if p == 0 {
			if req.GetScheme() == "https" {
				p = 443
			} else {
				p = 80
			}
		}
		target = &pocbase.TargetInfo{
			Host: host,
			Path: req.GetPath(),
			Port: p,
		}
	case pocbase.TransportTCP, pocbase.TransportUDP:
		asset := in.(*pocbase.ServiceAsset)
		target = &pocbase.TargetInfo{
			Host: asset.Host,
			Path: "",
			Port: asset.Port,
		}
	}
	pluginInfo := &pocbase.PluginInfo{
		ID:   poc.Id,
		Name: poc.Name,
	}
	fingerEvent := &pocbase.FingerprintEvent{
		Timestamp:   time.Now(),
		Plugin:      pluginInfo,
		Target:      target,
		Fingerprint: poc.Detail.Fingerprint,
	}
	return fingerEvent, nil
}

type setProgram struct {
	pg  cel.Program
	key string
}

func (poc *YamlPoc) compileVariables() (map[string]*expr.Type, error) {
	var setPrograms []*setProgram
	varContext := make(map[string]*expr.Type)
	if len(poc.Set.Content)%2 != 0 {
		return nil, fmt.Errorf("value error of %s set", poc.Name)
	}

	for i := 0; i < len(poc.Set.Content)-1; i += 2 {
		key := poc.Set.Content[i].Value
		value := poc.Set.Content[i+1].Value
		if key == "" || value == "" {
			return nil, fmt.Errorf("type error for %s set %v", poc.Name, poc.Set)
		}

		builder := expression.NewCELBuilder()
		if poc.Transport == pocbase.TransportHTTP {
			builder.WithHTTPType()
		} else {
			builder.WithNetworkType()
		}
		for n, t := range varContext {
			builder = builder.AddDeclarations(decls.NewVar(n, t))
		}

		if poc.NeedReverse {
			builder = builder.WithReverseType(poc.config.ReverClient)
		}

		//vdomains := new(oobadapter.OOBAdapter).GetValidationDomain()

		builder = builder.WithOobType(new(oobadapter.OOBAdapter))
		env, err := builder.Build()
		if err != nil {
			return nil, fmt.Errorf("can't build cel runner for %s set, %v", poc.Name, err)
		}
		ast, issues := env.Compile(value)
		if issues != nil && issues.Err() != nil {
			return nil, fmt.Errorf("compile error at %s set, %v", poc.Name, issues.Err())
		}
		varContext[key] = ast.ResultType()
		prg, err := env.Program(ast)
		if err != nil {
			return nil, fmt.Errorf("%s cel program error, %v", poc.Name, err)
		}
		setPrograms = append(setPrograms, &setProgram{prg, key})
	}
	poc.setPrograms = setPrograms
	return varContext, nil
}

func (poc *YamlPoc) compileExpression(varContext map[string]*expr.Type) error {
	for key, rule := range poc.Rules {
		builder := expression.NewCELBuilder()
		switch poc.Transport {
		case pocbase.TransportHTTP:
			builder = builder.WithHTTPType()
		case pocbase.TransportTCP, pocbase.TransportUDP:
			builder = builder.WithNetworkType()
		case pocbase.TransportSSH:
			builder = builder.WithSshType()
		default:
			return fmt.Errorf("unknow transport %s", poc.Transport)
		}
		for n, t := range varContext {
			builder = builder.AddDeclarations(decls.NewVar(n, t))
		}
		if poc.NeedReverse {
			builder = builder.WithReverseType(poc.config.ReverClient)
		}
		prg, err := builder.BuildAndCompile(rule.Expression, true)
		if err != nil {
			return fmt.Errorf("compile rule expression error id:【%v】- name:【%v】-err:%v", poc.Id, poc.Name, err)
		}
		poc.Rules[key].expProgram = prg

		var outputPrgs []*setProgram
		for i := range rule.Output.Content {
			if i%2 != 0 {
				continue
			}
			key := rule.Output.Content[i].Value
			value := rule.Output.Content[i+1].Value
			tmpEnv, err := builder.Build()
			if err != nil {
				return fmt.Errorf("compile rule expression error id:%v-name:%v-err:%v", poc.Id, poc.Name, err)
			}
			ast, issues := tmpEnv.Compile(value)
			if issues != nil && issues.Err() != nil {
				return issues.Err()
			}
			prg, err := tmpEnv.Program(ast, cel.EvalOptions(cel.OptOptimize))
			if err != nil {
				return fmt.Errorf("compile rule expression error id:%v-name:%v-err:%v", poc.Id, poc.Name, err)
			}
			outputPrgs = append(outputPrgs, &setProgram{
				pg:  prg,
				key: key,
			})
			builder.AddDeclarations(decls.NewVar(key, ast.ResultType()))
		}
		poc.Rules[key].outputPrograms = outputPrgs
	}
	return nil
}

func (poc *YamlPoc) SetProxy(proxy string) {
	poc.config.HttpClient.ClientOptions.Proxy = proxy
}

func (poc *YamlPoc) SetRetry(retry int) {
	poc.config.HttpClient.ClientOptions.FailRetries = retry
}

func (poc *YamlPoc) SetTimeout(timeout int) {
	poc.config.HttpClient.ClientOptions.ReadTimeout = timeout / 100
	poc.config.NetClient.Config.DialTimeout = time.Millisecond * time.Duration(timeout)
}
