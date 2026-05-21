package pocbase

// EventWriter 用于输出漏洞之类的事件信息
type EventWriter interface {
	Output(event Event) error
	Close()
}
