package proxy

import (
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/jcmturner/tlsinit/cert"
	"github.com/jcmturner/tlsinit/config"
)

func NewListener(c *config.Config, l cert.Loader) (ln net.Listener, err error) {
	crt, err := cert.Load(l)
	if err != nil {
		err = fmt.Errorf("could not load certificate: %v", err)
		return
	}
	config := tls.Config{
		Certificates:             []tls.Certificate{crt},
		Rand:                     rand.Reader,
		PreferServerCipherSuites: true,
		MinVersion:               tls.VersionTLS12,
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		CipherSuites:             []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		// The black list includes the cipher suite that TLS 1.2 makes mandatory, which means that TLS 1.2 deployments
		// could have non-intersecting sets of permitted cipher suites. To avoid this problem causing TLS handshake
		// failures, deployments of HTTP/2 that use TLS 1.2 MUST support TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
		// [TLS-ECDHE] with the P-256 elliptic curve [FIPS186].
	}
	return tls.Listen("tcp", c.ListenSocket, &config)
}

func ListenAndServe(c *config.Config, l cert.Loader) error {
	ln, err := NewListener(c, l)
	if err != nil {
		return err
	}

	defer ln.Close()

	return srv.ServeTLS(tcpKeepAliveListener{ln.(*net.TCPListener)}, certFile, keyFile)
}

// tcpKeepAliveListener sets TCP keep-alive timeouts on accepted connections.
type tcpKeepAliveListener struct {
	*net.TCPListener
}

func (ln tcpKeepAliveListener) Accept() (net.Conn, error) {
	tc, err := ln.AcceptTCP()
	if err != nil {
		return nil, err
	}
	tc.SetKeepAlive(true)
	tc.SetKeepAlivePeriod(3 * time.Minute)
	return tc, nil
}
