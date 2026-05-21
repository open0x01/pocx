# pocx Demo

一个最简单的命令行测试工具，仅供演示，不作为产品集成使用。

## 指定一个 yaml 脚本扫描目标网站

```
go run main.go -t https://yarx.koalr.me -p .\pocs\go-pprof-leak.yml
```

## 使用目录下的所有脚本扫描目标网站

```
go run main.go -t https://yarx.koalr.me -p .\pocs\
```

## 指定指纹信息，如果指纹不匹配，则 poc 不会运行

```
go run main.go -t https://yarx.koalr.me -p .\pocs\ -fingerprint openssh
```

## 指定并发数，默认 30，这里设置为 1，即一个一个运行

```
go run main.go -t https://yarx.koalr.me -p .\pocs\ -concurrent 1
```

## 本地启动反连平台并运行

rip 就是反连 ip 的意思，这个 ip 要求能够从靶站环境连接到当前机器，一般可以直接写机器的局域网地址或外网地址。

如果你想测试，可以先启动下面的代码运行一个简单的 ssrf server
```go
package main

import (
	"net/http"
)

func main() {
	http.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		_ = request.ParseForm()
		u := request.FormValue("url")
		http.Get(u)
	})
	http.ListenAndServe("127.0.0.1:8090", http.DefaultServeMux)
}

```
然后使用 reverse-test.yml 扫描这个临时的服务
```
go run main.go -t http://127.0.0.1:8090 -rip 127.0.0.1 -p ./pocs/reverse-test.yml
```

此时如果扫出漏洞则表示没问题。


## 测试 tcp 的扫描

tcp 目前的提供出版的支持，比如可以使用下面的 poc 测试一下 redis 未授权访问漏洞
```yaml
name: yaml-tcp-redis-unauth
transport: tcp
rules:
  r1:
    request:
      inputs:
        - data: "info\r\nquit\r\n"
      read_timeout: 3
    expression: response.raw.bcontains(b"redis_version")
    output:
      matches: '"redis_version:(?P<version>.*)".bsubmatch(response.raw)'
      version: matches["version"]
expression: r1()
detail:
  vulnerability:
    proof:
      version: '{{version}}'
```

将文件保存到 redis-unauth.yml, 准备好靶站，运行下列命令即可抛出漏洞：
```go
go run main.go -t 127.0.0.1:6379 -poc .\pocs\redis-unauth.yml
```


* request
  * http 类型
    1. url
       1. scheme    举例：request.url.scheme
       2. domain    举例：request.url.domain
       3. host      举例：request.url.host
       4. port      举例：request.url.port
       5. path      举例：request.url.path
       6. query     举例：request.url.query
       7. fragment  举例：request.url.fragment
    2. method       举例：request.method
    3. headers      举例：request.headers
    4. content_type 举例：request.content_type
    5. body         举例：request.body
    6. raw          举例：request.raw
  * tcp  类型
  * udp  类型
* response
  * http类型
    1. url
       1. scheme    举例：response.url.scheme
       2. domain    举例：response.url.domain
       3. host      举例：response.url.host
       4. port      举例：response.url.port
       5. path      举例：response.url.path
       6. query     举例：response.url.query
       7. fragment  举例：response.url.fragment
    2. status       举例：response.statue
    3. body         举例：response.body
    4. headers      举例：response.headers
    5. content_type 举例：response.content_type
    6. raw          举例：response.raw
    7. title        举例：response.title
    8. raw_header   举例：response.raw_header
    9. raw_cert     举例：response.raw_cert
  * tcp类型
    conn            举例：response.conn.source.port  response.conn.source.transport response.conn.destination.addr 
  * 反连类型
    1. url
        1. scheme    举例：reverse.url.scheme
        2. domain    举例：reverse.url.domain
        3. host      举例：reverse.url.host
        4. port      举例：reverse.url.port
        5. path      举例：reverse.url.path
        6. query     举例：reverse.url.query
        7. fragment  举例：reverse.url.fragment
    2. rmi           举例：reverse.rmi   
    3. ldap