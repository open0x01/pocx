package pocbase

import (
	"fmt"
	"github.com/iami317/shttp"
	"net"
	"strconv"
	"strings"
)

const (
	AssetUrlType     = "url"
	AssetServiceType = "service"
)

type Asset interface {
	Clone() Asset
	String() string
	Meta() *TaskMeta
}

type TaskMeta struct {
	TaskID string `json:"task_id" #:"任务ID(必填)"`
	Type   string `json:"type" #:"类型 url/service"`
}

// RequestAsset 是类型的输入
type RequestAsset struct {
	MetaInfo    *TaskMeta
	Req         *shttp.Request
	fingerprint *Fingerprint
}

func NewRequestAsset(meta *TaskMeta, req *shttp.Request) *RequestAsset {
	return &RequestAsset{
		MetaInfo:    meta,
		Req:         req,
		fingerprint: &Fingerprint{},
	}
}

func (r *RequestAsset) Clone() Asset {
	return &RequestAsset{
		MetaInfo: &TaskMeta{
			TaskID: r.MetaInfo.TaskID,
			Type:   r.MetaInfo.Type,
		},
		Req:         r.Req.Clone(),
		fingerprint: r.fingerprint.Clone(),
	}
}

func (r *RequestAsset) String() string {
	return fmt.Sprintf("[req] %s %s", r.Req.GetMethod(), r.Req.GetUrl())
}

func (r *RequestAsset) Meta() *TaskMeta {
	return r.MetaInfo
}

// ServiceAsset 服务资产
type ServiceAsset struct {
	MetaInfo *TaskMeta

	Host    string `json:"host" #:"ip or domain (必填)"`
	Port    int    `json:"port" #:"port (必填)"`
	IsIPv4  bool   `json:"is_ipv4" #:"是否为ipv4 (必填)"`
	Network string `json:"network" #:"tcp or udp (必填)"`
}

func (a *ServiceAsset) Clone() Asset {
	newS := *a
	return &newS
}

func (a *ServiceAsset) Meta() *TaskMeta {
	return a.MetaInfo
}

func (a *ServiceAsset) String() string {
	return net.JoinHostPort(a.Host, strconv.Itoa(a.Port))
}

func (a *ServiceAsset) Address() string {
	return a.String()
}

func NewServiceAsset(addr string, network string) (*ServiceAsset, error) {
	if strings.Contains(addr, "://") {
		addr = strings.Split(addr, "://")[1]
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		return nil, err
	}
	if err != nil {
		return nil, err
	}
	return &ServiceAsset{
		Host:    host,
		Port:    p,
		IsIPv4:  true,
		Network: network,
	}, nil
}
