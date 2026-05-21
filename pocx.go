package pocx

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/iami317/logx"
	"github.com/iami317/pocx/pocbase"
	"github.com/iami317/pocx/snet"
	"github.com/iami317/reverkit"
	"github.com/iami317/shttp"
	"github.com/zmap/zgrab2/lib/ssh"
	"gopkg.in/yaml.v3"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

// Config 用于初始化的配置
type Config struct {
	Logger      *logx.Logger
	Writer      pocbase.EventWriter
	HttpClient  *shttp.Client
	NetClient   *snet.Client
	ReverClient *reverkit.Client
	SshConfig   *ssh.ClientConfig
}

const _ctx_config = "_pocx_config"

var ErrConfigNotFound = errors.New("config not found in context")

const (
	Yml = "yaml"
	Rpy = "rpy"
	Py  = "py"
)

func ContextConfig(ctx context.Context) (*Config, error) {
	conf := ctx.Value(_ctx_config)
	config, ok := conf.(*Config)
	if !ok {
		return nil, ErrConfigNotFound
	}
	return config, nil
}

func LoadSinglePOC(content []byte, class string) (pocbase.ScanPlugin, error) {
	switch class {
	//case Py:
	//	return LoadPythonPOC(content)
	case Yml:
		return LoadYamlPOC(content)
		//case Rpy:
		//	return LoadPythonPOC(content)
	}
	return nil, fmt.Errorf("type error")
}

/*
func LoadRpcPOC(content []byte) (pocbase.ScanPlugin, error) {
	var poc RpcPoc
	err := json.Unmarshal(content, &poc)
	if err != nil {
		return nil, err
	}
	return &poc, nil
}

func LoadPythonPOC(content []byte) (pocbase.ScanPlugin, error) {
	var poc RpcPoc

	poc.Data = content
	return &poc, nil
}
*/

func LoadYamlPOC(content []byte) (pocbase.ScanPlugin, error) {
	var poc YamlPoc
	err := yaml.Unmarshal(content, &poc)
	if err != nil {
		return nil, fmt.Errorf("unmarshal poc: %v;file content:\n%v", err, string(content))
	}
	poc.Transport = strings.ToLower(poc.Transport)
	switch poc.Transport {
	case pocbase.TransportHTTP:
		for k, v := range poc.Rules {
			data, _ := yaml.Marshal(v.Request)
			var rule httpRule
			err = yaml.Unmarshal(data, &rule)
			if err != nil {
				return nil, fmt.Errorf("unmarshal rule: %v -- file content:%v", err, string(content))
			}
			poc.Rules[k].Request = &rule
		}
	case pocbase.TransportTCP, pocbase.TransportUDP:
		for k, v := range poc.Rules {
			data, _ := yaml.Marshal(v.Request)
			var rule networkRule
			err = yaml.Unmarshal(data, &rule)
			if err != nil {
				return nil, fmt.Errorf("unmarshal rule: %v -- file content:", err, string(content))
			}
			poc.Rules[k].Request = &rule
		}
	case pocbase.TransportSSH:
		for k, v := range poc.Rules {
			data, _ := yaml.Marshal(v.Request)
			var rule sshRule
			err = yaml.Unmarshal(data, &rule)
			if err != nil {
				return nil, fmt.Errorf("unmarshal rule: %v -- file content:", err, string(content))
			}
			poc.Rules[k].Request = &rule
		}
	default:
		return nil, fmt.Errorf("unknow transport type [%s] -- file content: %v", poc.Transport, string(content))
	}
	poc.NeedReverse = bytes.Contains(content, []byte("newReverse"))
	return &poc, nil
}

func LoadPocsInDir(dir string) ([]pocbase.ScanPlugin, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var ret []pocbase.ScanPlugin
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml") {
			data, err := ioutil.ReadFile(filepath.Join(dir, name))
			if err != nil {
				return ret, err
			}
			poc, err := LoadSinglePOC(data, Yml)
			if err != nil {
				return ret, err
			}
			ret = append(ret, poc)
		}
		if strings.HasSuffix(name, ".py") {
			data, err := ioutil.ReadFile(filepath.Join(dir, name))
			if err != nil {
				return ret, err
			}
			poc, err := LoadSinglePOC(data, Rpy)
			if err != nil {
				return ret, err
			}
			ret = append(ret, poc)
		}
	}
	return ret, nil
}

func ContextWithConfig(ctx context.Context, config *Config) context.Context {
	return context.WithValue(ctx, _ctx_config, config)
}
