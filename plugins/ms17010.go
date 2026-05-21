package plugins

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/open0x01/pocx"
	"github.com/open0x01/pocx/pocbase"
	"github.com/pkg/errors"
	"strings"
	"time"
)

var (
	negotiateProtocolRequest, _  = hex.DecodeString("00000085ff534d4272000000001853c00000000000000000000000000000fffe00004000006200025043204e4554574f524b2050524f4752414d20312e3000024c414e4d414e312e30000257696e646f777320666f7220576f726b67726f75707320332e316100024c4d312e325830303200024c414e4d414e322e3100024e54204c4d20302e313200")
	sessionSetupRequest, _       = hex.DecodeString("00000088ff534d4273000000001807c00000000000000000000000000000fffe000040000dff00880004110a000000000000000100000000000000d40000004b000000000000570069006e0064006f007700730020003200300030003000200032003100390035000000570069006e0064006f007700730020003200300030003000200035002e0030000000")
	treeConnectRequest, _        = hex.DecodeString("00000060ff534d4275000000001807c00000000000000000000000000000fffe0008400004ff006000080001003500005c005c003100390032002e003100360038002e003100370035002e003100320038005c00490050004300240000003f3f3f3f3f00")
	transNamedPipeRequest, _     = hex.DecodeString("0000004aff534d42250000000018012800000000000000000000000000088ea3010852981000000000ffffffff0000000000000000000000004a0000004a0002002300000007005c504950455c00")
	trans2SessionSetupRequest, _ = hex.DecodeString("0000004eff534d4232000000001807c00000000000000000000000000008fffe000841000f0c0000000100000000000000a6d9a40000000c00420000004e0001000e000d0000000000000000000000000000")
)

type Ms17010 struct {
	Id     string   `yaml:"id" #:"id 信息"`
	Name   string   `yaml:"name" #:"插件名称"`
	Tags   []string `yaml:"tags"`
	config *pocx.Config
}

func NewMs17010() *Ms17010 {
	return &Ms17010{
		// CVE-2017-0146
		Id:   "CNNVD-201703-723",
		Name: "Ms17010",
		Tags: []string{"microsoft"},
	}
}

func (m17 *Ms17010) Init(ctx context.Context) error {
	config, err := pocx.ContextConfig(ctx)
	if err != nil {
		return err
	}

	m17.config = config
	return nil
}

func (m17 *Ms17010) Meta() *pocbase.MetaInfo {
	return &pocbase.MetaInfo{
		Plugin: &pocbase.PluginInfo{
			ID:   m17.Id,
			Name: m17.Name,
		},
	}
}
func (m17 *Ms17010) Match(ctx context.Context, in []string) bool {
	if len(in) == 0 || len(m17.Tags) == 0 {
		return true
	} else {
		if len(in) > 0 {
			for _, v := range in {
				for _, y := range m17.Tags {
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
func (m17 *Ms17010) Scan(ctx context.Context, in interface{}) (pocbase.SnapShot, pocbase.Event, error) {
	var snapShot pocbase.SnapShot
	srv, isService := in.(*pocbase.ServiceAsset)
	if !isService {
		return snapShot, nil, fmt.Errorf("not service asset")
	}
	ip := srv.Host
	//conn, err := net.DialTimeout("tcp", ip+":445", time.Duration(5)*time.Second)
	conn, err := m17.config.NetClient.Dial(ctx, srv)
	if err != nil {
		return snapShot, nil, err
	}
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()
	//err = conn.SetDeadline(time.Now().Add(time.Duration(5) * time.Second))
	//if err != nil {
	//	return nil, err
	//}
	_, err = conn.Write(negotiateProtocolRequest)
	if err != nil {
		return snapShot, nil, err
	}
	reply := make([]byte, 1024)
	if n, err := conn.Read(reply); err != nil || n < 36 {
		return snapShot, nil, err
	}

	if binary.LittleEndian.Uint32(reply[9:13]) != 0 {
		return snapShot, nil, err
	}

	_, err = conn.Write(sessionSetupRequest)
	if err != nil {
		return snapShot, nil, err
	}
	n, err := conn.Read(reply)
	if err != nil || n < 36 {
		return snapShot, nil, err
	}

	if binary.LittleEndian.Uint32(reply[9:13]) != 0 {
		var Err = errors.New("can't determine whether target is vulnerable or not")
		return snapShot, nil, Err
	}

	var os string
	sessionSetupResponse := reply[36:n]
	if wordCount := sessionSetupResponse[0]; wordCount != 0 {
		byteCount := binary.LittleEndian.Uint16(sessionSetupResponse[7:9])
		if n != int(byteCount)+45 {
			return snapShot, nil, fmt.Errorf("[-]", ip+":445", "ms17010 invalid session setup AndX response")
		} else {
			for i := 10; i < len(sessionSetupResponse)-1; i++ {
				if sessionSetupResponse[i] == 0 && sessionSetupResponse[i+1] == 0 {
					os = string(sessionSetupResponse[10:i])
					os = strings.Replace(os, string([]byte{0x00}), "", -1)
					break
				}
			}
		}

	}
	userID := reply[32:34]
	treeConnectRequest[32] = userID[0]
	treeConnectRequest[33] = userID[1]
	_, err = conn.Write(treeConnectRequest)
	if err != nil {
		return snapShot, nil, err
	}
	if n, err := conn.Read(reply); err != nil || n < 36 {
		return snapShot, nil, err
	}

	treeID := reply[28:30]
	transNamedPipeRequest[28] = treeID[0]
	transNamedPipeRequest[29] = treeID[1]
	transNamedPipeRequest[32] = userID[0]
	transNamedPipeRequest[33] = userID[1]

	_, err = conn.Write(transNamedPipeRequest)
	if err != nil {
		return snapShot, nil, err
	}
	if n, err := conn.Read(reply); err != nil || n < 36 {
		return snapShot, nil, err
	}

	if reply[9] == 0x05 && reply[10] == 0x02 && reply[11] == 0x00 && reply[12] == 0xc0 {
		//result := fmt.Sprintf("[+] %s\tMS17-010\t(%s)", ip, os)
		//golog.Warn("11", result)
		return snapShot, &pocbase.VulEvent{
			Timestamp: time.Now(),
			Plugin: &pocbase.PluginInfo{
				ID:   m17.Id,
				Name: m17.Name,
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

func (m17 *Ms17010) Close() {}

func (m17 *Ms17010) SetProxy(proxy string) {}

func (m17 *Ms17010) SetRetry(retry int) {}

func (m17 *Ms17010) SetTimeout(timeout int) {}
