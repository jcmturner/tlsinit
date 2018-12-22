package config

import (
	"net"
	"time"
)

type Config struct {
	ListenSocket   string
	CertLoader     CertLoader
	ReloadDuration time.Duration
	Downstream     Downstream
}

type Downstream struct {
	Socket    string
	Addr      *net.TCPAddr
	TLS       bool
	TLSVerify bool
	TrustCA   string
}

func (d *Downstream) ResolveDownstream() (err error) {
	d.Addr, err = net.ResolveTCPAddr("tcp", d.Socket)
	return
}
