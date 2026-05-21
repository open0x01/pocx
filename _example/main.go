package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"github.com/iami317/hubur"
	"github.com/iami317/logx"
	"github.com/open0x01/pocx"
	"github.com/open0x01/pocx/plugins"
	"github.com/open0x01/pocx/pocbase"
	"github.com/open0x01/pocx/snet"
	"github.com/open0x01/reverkit"
	"github.com/iami317/shttp"
	"github.com/kataras/pio"
	"github.com/urfave/cli/v2"
	"github.com/zmap/zgrab2/lib/ssh"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

func RunApp() {
	app := cli.NewApp()
	app.Usage = ""
	app.Name = "pocx"
	app.Version = "0.3 beta"
	app.Description = ""
	app.HelpName = "-h"
	app.Flags = []cli.Flag{
		&cli.StringFlag{
			Name:    "target",
			Aliases: []string{"t"},
			Usage:   "Specify a target URL [e.g. -url https://example.com]",
		},
		&cli.StringFlag{
			Name:    "target-file",
			Aliases: []string{"tF"},
			Usage:   "Select a URL file for batch identification",
		},
		&cli.StringFlag{
			Name:    "poc",
			Aliases: []string{"p"},
			Usage:   "yaml poc or yaml fingerprint Or Select a yaml file path for batch identification",
		},
		&cli.StringFlag{
			Name:    "reverse-ip",
			Aliases: []string{"rip"},
			Usage:   "set up the ip will help to launch a reverse server, ex: 127.0.0.1",
		},
		&cli.IntFlag{
			Name:    "thread",
			Aliases: []string{"c"},
			Value:   30,
			Usage:   "Number of concurrent threads",
		},
		&cli.StringFlag{
			Name:    "proxy",
			Aliases: []string{"pr"},
			Usage:   "Use proxy scan, support http/socks5 protocol [e.g. --proxy socks5://127.0.0.1:1080]",
		},
		&cli.BoolFlag{
			Name:  "verbose",
			Usage: "set log level to debug",
		},
		&cli.StringFlag{
			Name:    "python-server",
			Aliases: []string{"ps"},
			Usage:   "rpc-server",
		},
	}
	app.Action = RunServer
	err := app.Run(os.Args)
	if err != nil {
		log.Fatalf("engin err: %v", err)
		return
	}
}

func main() {
	RunApp()
}

func RunServer(c *cli.Context) error {
	t := time.Now()
	logger := logx.New()
	logger.SetTimeFormat("2006/01/02 15:04:05.000")
	var pocs []pocbase.ScanPlugin
	var targets []string
	var err error
	target := c.String("target")
	targetFile := c.String("target-file")
	yaml := c.String("poc")
	thread := c.Int("thread")
	proxy := c.String("proxy")
	if target == "" && yaml == "" && targetFile == "" {
		return fmt.Errorf("target And poc must not be empty")
	}
	if target != "" && targetFile != "" {
		return fmt.Errorf("target or targetFile cannot be enabled at the same time")
	}
	if targetFile != "" {
		// 从文件读取目标
		fi, err := os.Open(targetFile)
		defer fi.Close()
		if err != nil {
			return err
		}
		br := bufio.NewReader(fi)
		for {
			line, _, c := br.ReadLine()
			if c == io.EOF {
				break
			}
			targets = append(targets, string(line))
		}
	} else {
		targets = []string{target}
	}
	//配置yaml文件读取
	if strings.HasSuffix(yaml, ".yaml") || strings.HasSuffix(yaml, ".yml") {
		data, err := ioutil.ReadFile(yaml)
		if err != nil {
			return err
		}
		p, err := pocx.LoadSinglePOC(data, pocx.Yml)
		if err != nil {
			return err
		}
		pocs = []pocbase.ScanPlugin{p}

	} else if strings.HasSuffix(yaml, ".py") {
		data, err := ioutil.ReadFile(yaml)
		if err != nil {
			return err
		}
		p, err := pocx.LoadSinglePOC(data, pocx.Rpy)
		if err != nil {
			return err
		}
		pocs = []pocbase.ScanPlugin{p}
	} else if yaml == "cve20200769" {
		pocs = append(pocs, plugins.Newcve20200796())
	} else if yaml == "ms17010" {
		pocs = append(pocs, plugins.NewMs17010())
	} else if yaml == "ms12020" {
		pocs = append(pocs, plugins.NewMs12020())
	} else if yaml == "cve20190708" {
		pocs = append(pocs, plugins.Newcve20190708())
	} else {
		pocs, err = pocx.LoadPocsInDir(yaml)
		if err != nil {
			return err
		}
		//pocs = append(pocs, plugins.Newcve20200796(), plugins.NewMs17010(), plugins.Newcve20190708())
	}

	defer func() {
		for _, poc := range pocs {
			poc.Close()
		}
	}()

	//配置代理
	clientOptions := shttp.DefaultClientOptions()
	clientOptions.DialTimeout = 5
	clientOptions.SoloConn = true
	clientOptions.EnableHTTP2 = true
	clientOptions.FailRetries = 0
	clientOptions.DisableKeepAlives = true
	clientOptions.MaxConnsPerHost = 1
	if len(proxy) > 0 {
		logger.Infof("starting proxy %v", proxy)
		clientOptions.Proxy = proxy
	}

	if c.Bool("verbose") {
		clientOptions.Debug = true
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var reverClient *reverkit.Client
	if c.String("reverse-ip") != "" {
		logger.Info("starting a local reverse server")
		freePort, _ := hubur.GetFreePort()
		serverConfig := &reverkit.ServerConfig{
			DBFilePath: "./reverkit.db",
			Token:      hubur.RandLower(8),
			HTTPServerConfig: reverkit.HTTPServerConfig{
				Enabled:    true,
				ListenIP:   c.String("reverse-ip"),
				ListenPort: strconv.Itoa(freePort),
				IPHeader:   "",
			},
		}
		server, err := reverkit.NewServer(serverConfig)
		if err != nil {
			return err
		}
		err = server.Start(ctx)
		if err != nil {
			return err
		}
		defer server.Close()
		reverClient, err = reverkit.NewClient(ctx, &reverkit.ClientConfig{
			Token:       serverConfig.Token,
			HTTPBaseURL: fmt.Sprintf("http://%s:%d", c.String("reverse-ip"), freePort),
		})
		if reverClient == nil && err != nil {
			return fmt.Errorf("reverse server start err:%v", err.Error())
		}
	}

	httpClient, err := shttp.NewClient(clientOptions, nil)
	if err != nil {
		return err
	}
	netClient := snet.NewClient(&snet.ClientConfig{
		DialTimeout:  5 * time.Second,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	})

	config := &pocx.Config{
		Logger:      logger,
		HttpClient:  httpClient,
		NetClient:   netClient,
		SshConfig:   ssh.MakeSSHConfig(),
		ReverClient: reverClient,
	}

	//初始化poc对象
	ctx = pocx.ContextWithConfig(ctx, config)
	for _, yamlPoc := range pocs {
		err := yamlPoc.Init(ctx)
		if err != nil {
			logger.Error(err)
			return err
		}
	}

	group := hubur.NewSizedWaitGroup(thread)
	for _, v := range targets {
		//time.Sleep(time.Second * 10)
		var in pocbase.Asset
		if strings.HasPrefix(v, "http") {
			req, _ := http.NewRequest(http.MethodGet, v, nil)
			in = pocbase.NewRequestAsset(
				&pocbase.TaskMeta{
					Type: pocbase.AssetUrlType,
				},
				&shttp.Request{
					RawRequest: req,
				},
			)
		} else {
			in, err = pocbase.NewServiceAsset(v, "tcp")
			if err != nil {
				logger.Error(err)
				continue
			}
		}
		for _, yamlPoc := range pocs {
			err := group.AddWithContext(ctx)
			if err != nil {
				logger.Error(err)
				return err
			}
			yamlPoc := yamlPoc
			go func(v string) {
				//t := time.Now()
				defer func() {
					group.Done()
				}()
				snap, res, err := yamlPoc.Scan(ctx, in.Clone())
				logger.Verbosef("checking %s using %s", in, yamlPoc.Meta().Plugin.Name)

				if err != nil {
					if strings.Contains(err.Error(), "match nil") {
						logger.Verbosef(pio.Rich(fmt.Sprintf("Target => %s run finished,err:%v", v, err.Error()), pio.Cyan))
					} else {
						logger.Verbosef("Target => %s Run Finished,ERR:%v Latency => %v", v, err.Error(), time.Since(t).Seconds())
					}
					return
				}
				if vulEvent, ok := res.(*pocbase.VulEvent); ok {
					//fmt.Println("snap.Content", string(snap.Content[0].RequestRaw))
					fmt.Println("vulEvent.Target.Path", snap.Content[0].Request.GetUrl())
					//fmt.Println("vulEvent.Target.Host", vulEvent.Target.Host)
					//fmt.Println("vulEvent.Target.Port", vulEvent.Target.Port)
					//fmt.Println("vulEvent.SnapShot", string(vulEvent.SnapShot[0].RequestRaw))
					extractedInfo, _ := json.Marshal(vulEvent.Details.ExtractedInfo)
					logger.Silentf("**Target** => %s **Vul** => %s **Info** =>%#v", v, vulEvent.Plugin.Name, string(extractedInfo))
					return
				}

				//if fingerEvent, ok := res.(*pocbase.FingerprintEvent); ok {
				//	logger.Silentf("[Target] => %s [Script] => %s [Product] =>%#v", v, fingerEvent.Plugin.Name, fingerEvent.Fingerprint.Product)
				//	return
				//}

				return
			}(v)
		}
	}

	group.Wait()
	logger.Infof("%s", pio.Rich(fmt.Sprintf("run finished  目标总数:%v个，耗时:%v", len(targets), time.Since(t)), pio.Cyan))
	return nil
}
