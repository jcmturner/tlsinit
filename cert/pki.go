package cert

import (
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"os"
)

type Loader interface {
	KeyPair() (pub, pvt io.Reader, err error)
}

type FileLoader struct {
	PrivateKeyPath string
	PublicCertPath string
}

func (l *FileLoader) KeyPair() (pub, pvt io.Reader, err error) {
	pub, err = os.Open(l.PublicCertPath)
	if err != nil {
		return
	}
	pvt, err = os.Open(l.PrivateKeyPath)
	if err != nil {
		return
	}
	return
}

func Load(l Loader) (tls.Certificate, error) {
	pub, pvt, err := l.KeyPair()
	if err != nil {
		return tls.Certificate{}, err
	}
	cb, err := ioutil.ReadAll(pub)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("could not read public key: %v", err)
	}
	kb, err := ioutil.ReadAll(pvt)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("could not read private key: %v", err)
	}
	return tls.X509KeyPair(cb, kb)
}
