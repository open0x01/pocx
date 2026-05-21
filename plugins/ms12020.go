package plugins

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/open0x01/pocx"
	"github.com/open0x01/pocx/pocbase"
	"strconv"
	"strings"
	"time"
)

var (
	connectionRequest, _  = hex.DecodeString("030000130ee000000000000100080000000000")
	initialPdu, _         = hex.DecodeString("0300006502f0807f655b0401010401010101ff30190201220201200201000201010201000201010202ffff02010230180201010201010201010201010201000201010201ff02010230190201ff0201ff0201ff0201010201000201010202ffff0201020400")
	userRequest, _        = hex.DecodeString("0300000802f08028")
	channelJoinRequest, _ = hex.DecodeString("0300000c02f08038")
)

type Ms12020 struct {
	Id     string   `yaml:"id" #:"id 信息"`
	Name   string   `yaml:"name" #:"插件名称"`
	Tags   []string `yaml:"tags"`
	config *pocx.Config
}

func NewMs12020() *Ms12020 {
	return &Ms12020{
		// CVE-2012-0002
		Id:   "CNNVD-201203-241",
		Name: "Ms12020",
		// todo 192.168.106.50:3389
		Tags: []string{"microsoft"},
	}
}

func (m12 *Ms12020) Init(ctx context.Context) error {
	config, err := pocx.ContextConfig(ctx)
	if err != nil {
		return err
	}

	m12.config = config
	return nil
}
func Hex2Dec(val string) int {
	n, err := strconv.ParseUint(val, 16, 32)
	if err != nil {
		fmt.Println(err)
	}
	return int(n)
}

func (m12 *Ms12020) Meta() *pocbase.MetaInfo {
	return &pocbase.MetaInfo{
		Plugin: &pocbase.PluginInfo{
			ID:   m12.Id,
			Name: m12.Name,
		},
	}
}
func (m12 *Ms12020) Match(ctx context.Context, in []string) bool {
	if len(in) == 0 || len(m12.Tags) == 0 {
		return true
	} else {
		if len(in) > 0 {
			for _, v := range in {
				for _, y := range m12.Tags {
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
func Int2Bytes(num int) []byte {
	i32 := int32(num)
	bBuffer := bytes.NewBuffer([]byte{})
	binary.Write(bBuffer, binary.BigEndian, i32)
	return bBuffer.Bytes()
}
func (m12 *Ms12020) Scan(ctx context.Context, in interface{}) (pocbase.SnapShot, pocbase.Event, error) {
	var snapShot pocbase.SnapShot
	srv, isService := in.(*pocbase.ServiceAsset)
	if !isService {
		return snapShot, nil, fmt.Errorf("not service asset")
	}
	conn, err := m12.config.NetClient.Dial(ctx, srv)
	if err != nil {
		return snapShot, nil, err
	}
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()
	_, err = conn.Write(connectionRequest)
	if err != nil {
		return snapShot, nil, err
	}
	reply := make([]byte, 8192)
	if _, err := conn.Read(reply); err != nil {
		return snapShot, nil, err
	}
	encodeData := hex.EncodeToString(reply)
	if !strings.Contains(encodeData, "030000130ed000001234000201080000000000") && !strings.Contains(encodeData, "030000130ed000001234000201080000000000") {
		return snapShot, nil, fmt.Errorf("ERROR: This isn't RDP")
	}
	_, err = conn.Write(initialPdu)
	if err != nil {
		return snapShot, nil, err
	}
	_, err = conn.Write(userRequest)
	if err != nil {
		return snapShot, nil, err
	}
	reply1 := make([]byte, 8192)
	if _, err = conn.Read(reply1); err != nil {
		return snapShot, nil, err
	}
	user1 := reply1[9:11]
	_, err = conn.Write(userRequest)
	if err != nil {
		return snapShot, nil, err
	}
	reply2 := make([]byte, 8192)
	if _, err = conn.Read(reply2); err != nil {
		return snapShot, nil, err
	}
	user2Int := Hex2Dec(hex.EncodeToString(reply2[9:11])) + 1001
	user2 := Int2Bytes(user2Int)
	_, err = conn.Write(channelJoinRequest)
	if err != nil {
		return snapShot, nil, err
	}
	_, err = conn.Write(user1)
	if err != nil {
		return snapShot, nil, err
	}
	_, err = conn.Write(user2)
	if err != nil {
		return snapShot, nil, err
	}
	reply3 := make([]byte, 8192)
	if _, err = conn.Read(reply3); err != nil {
		return snapShot, nil, err
	}
	if hex.EncodeToString(reply3[7:9]) == "3e00" {
		return snapShot, &pocbase.VulEvent{
			Timestamp: time.Now(),
			Plugin: &pocbase.PluginInfo{
				ID:   m12.Id,
				Name: m12.Name,
			},
			Details: &pocbase.VulDetail{},
			Target: &pocbase.TargetInfo{
				Host: srv.Host,
				Path: "",
				Port: srv.Port,
			},
		}, nil
	}
	return snapShot, nil, nil

}

func (m12 *Ms12020) Close() {}

func (m12 *Ms12020) SetProxy(proxy string) {}

func (m12 *Ms12020) SetRetry(retry int) {}

func (m12 *Ms12020) SetTimeout(timeout int) {}
