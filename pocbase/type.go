package pocbase

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/iami317/shttp"
	"net"
	"strconv"
	"time"
)

const (
	TransportHTTP = "http"
	TransportTCP  = "tcp"
	TransportUDP  = "udp"
	TransportSSH  = "ssh"
)

type Event interface {
	fmt.Stringer
	json.Marshaler
}

// Fingerprint 指纹信息
type Fingerprint struct {
	Author         string `json:"author" yaml:"author"`
	Softhard       string `json:"softhard" yaml:"softhard"`
	Tags           string `json:"tags" yaml:"tags" #:"标签"`
	Product        string `json:"product" yaml:"product"`
	Company        string `json:"company" yaml:"company"`
	ParentCategory string `json:"parent_category" yaml:"parent_category"`
	Category       string `json:"category" yaml:"category"`
	Description    string `json:"description" yaml:"description"`
}

// IsEmpty 如果 Product 是空，那么这个就认为是无效的
func (f *Fingerprint) IsEmpty() bool {
	return f.Product == ""
}

func (f *Fingerprint) Clone() *Fingerprint {
	newf := *f
	return &newf
}

// FingerprintEvent 输出指纹信息时的事件
type FingerprintEvent struct {
	Timestamp time.Time   `json:"timestamp,omitempty"`   // 漏洞发现时间
	Plugin    *PluginInfo `json:"plugin_info,omitempty"` // 插件基础信息
	Target    *TargetInfo `json:"assets_info,omitempty"` // 资产信息
	Fingerprint
}

func (f *FingerprintEvent) String() string {
	return fmt.Sprintf("[fingerprint: %s] %s", f.Plugin.ID, f.Target)
}

func (f *FingerprintEvent) MarshalJSON() ([]byte, error) {
	return json.Marshal(f)
}

// VulEvent 漏洞信息的事件
type VulEvent struct {
	Timestamp time.Time          `json:"timestamp,omitempty"`   // 漏洞发现时间
	Target    *TargetInfo        `json:"assets_info,omitempty"` // 资产信息
	Plugin    *PluginInfo        `json:"plugin_info,omitempty"` // 插件基础信息
	Details   *VulDetail         `json:"details,omitempty"`     // 漏洞细节
	SnapShot  []*SnapShotContent `json:"snap_shot,omitempty"`
}

func (v *VulEvent) String() string {
	return fmt.Sprintf("[Target:%s vuln:%s vulName:%s]", v.Target, v.Plugin.ID, v.Plugin.Name)
}

func (v *VulEvent) MarshalJSON() ([]byte, error) {
	return json.Marshal(v)
}

// PluginInfo 插件信息
type PluginInfo struct {
	ID   string `json:"id,omitempty"`   // id, 用于从基础漏洞库取漏洞描述
	Name string `json:"name,omitempty"` // name, 人可读的信息
}

// TargetInfo 资产信息
type TargetInfo struct {
	Host string `json:"host,omitempty"` // domain or ip
	Port int    `json:"port,omitempty"` // 端口
	Path string `json:"path,omitempty"` // 路径
}

func (t *TargetInfo) String() string {
	return fmt.Sprintf("%s/%s", net.JoinHostPort(t.Host, strconv.Itoa(t.Port)), t.Path)
}

type SnapShot struct {
	SrcIp   string
	SrcPort int
	DstIp   string
	DstPort int
	Content []SnapShotContent
}
type SnapShotContent struct {
	Request     *shttp.Request
	RequestRaw  []byte
	Response    *shttp.Response
	ResponseRaw []byte
}

// VulDetail 漏洞细节
type VulDetail struct {
	Payload       string                 `json:"payload"`                  // payload
	SnapShot      []SnapShotContent      `json:"snapshot,omitempty"`       // 漏洞探测过程中的请求与响应 Snapshot [][2][]byte
	ExtractedInfo map[string]interface{} `json:"extracted_info,omitempty"` // 额外信息, 证明漏洞存在的信息，例如未授权漏洞获取到的组件版本

}

// 插件基础信息
type MetaInfo struct {
	Plugin *PluginInfo
}

// ScanPlugin 是一个扫描类插件的通用接口定义
type ScanPlugin interface {
	Init(ctx context.Context) error
	Meta() *MetaInfo
	Match(ctx context.Context, in []string) bool
	Scan(ctx context.Context, in interface{}) (SnapShot, Event, error)
	Close()
	SetProxy(proxy string)
	SetRetry(retry int)
	SetTimeout(timeout int)
}
