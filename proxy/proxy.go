package proxy

import (
	"io"
	"net"
	"time"

	"github.com/jcmturner/tlsinit/config"
)

func dialTCP(c *config.Config) (conn *net.TCPConn, err error) {
	err = c.Downstream.ResolveDownstream()
	if err != nil {
		return
	}
	conn, err = net.DialTCP("tcp", nil, c.Downstream.Addr)
	if err != nil {
		return
	}
	err = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err != nil {
		return
	}
	err = conn.SetKeepAlive(true)
	return
}

func proxyTraffic(in, out net.Conn) {
	go func() {
		//defer in.Close()
		//defer out.Close()
		io.Copy(out, in)
	}()
	go func() {
		//defer in.Close()
		//defer out.Close()
		io.Copy(in, out)
	}()
}
