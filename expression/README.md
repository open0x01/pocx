# expr

一个简易实现的表达式引擎，基于 cel-go, 类型注入基于 protobuf

## proto
在当前目录运行

```bash
protoc.exe --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative .\types.proto

protoc --go_out=. ./expression/types.proto
```
## 特别注意

由于反连服务有类似 `newReverse().url` 的写法，自动生成的 url 实现的 String() 方法不太对，需要在代码生成完生动改一下，
感觉应该有更好的办法来做这件事。

比如需要这样改：

```go
func (x *UrlType) String() string {
	s := fmt.Sprintf("%s://%s%s", x.Scheme, x.Host, x.Path)
	if x.Query != "" {
		s += "?" + x.Query
	}
	if x.Fragment != "" {
		s += "#" + x.Fragment
	}
	return s
}
```