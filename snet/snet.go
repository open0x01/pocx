package snet

import (
	"context"
	"github.com/open0x01/pocx/pocbase"
	"net"
	"time"
)

type ClientConfig struct {
	DialTimeout  time.Duration
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
}

type Client struct {
	Config *ClientConfig
}

func NewClient(config *ClientConfig) *Client {
	return &Client{Config: config}
}

func (c *Client) Dial(ctx context.Context, srv *pocbase.ServiceAsset) (net.Conn, error) {
	dialer := &net.Dialer{
		Timeout: c.Config.DialTimeout,
	}
	conn, err := dialer.DialContext(ctx, srv.Network, srv.Address())
	conn = &timeoutConn{
		Conn:         conn,
		readTimeout:  c.Config.ReadTimeout,
		writeTimeout: c.Config.WriteTimeout,
	}
	return conn, err
}

type timeoutConn struct {
	net.Conn
	readTimeout  time.Duration
	writeTimeout time.Duration
}

func (t *timeoutConn) Read(b []byte) (n int, err error) {
	if t.readTimeout > 0 {
		err := t.Conn.SetReadDeadline(time.Now().Add(t.readTimeout))
		if err != nil {
			return 0, err
		}
	}
	return t.Conn.Read(b)
}

func (t *timeoutConn) Write(b []byte) (n int, err error) {
	if t.writeTimeout > 0 {
		err := t.Conn.SetWriteDeadline(time.Now().Add(t.writeTimeout))
		if err != nil {
			return 0, err
		}
	}
	return t.Conn.Write(b)
}
