package proxy

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/jcmturner/tlsinit/config"
)

func testServer(response string, tls bool) *httptest.Server {
	if tls {
		s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			testHandler(w, r, response)
		}))
		return s
	} else {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			testHandler(w, r, response)
		}))
		return s
	}
}

func testHandler(w http.ResponseWriter, r *http.Request, response string) {
	w.Header().Set("Content-Type", "application/json")
	defer r.Body.Close()
	body, _ := ioutil.ReadAll(r.Body)
	w.Header().Set("X-Postvalue", string(body))
	w.Header().Set("X-Queryvalue", r.URL.Query().Get("queryKey"))
	fmt.Fprintln(w, response)
}

func TestTrafficCopy(t *testing.T) {
	s := testServer("Test server response.", false)
	defer s.Close()
	c := new(config.Config)
	c.Downstream.Socket = s.Listener.Addr().String()
	fmt.Fprintf(os.Stderr, "downstream addr: %s", c.Downstream.Socket)

	b, p := GenerateSelfSignedTLSKeyPairData(t)
	pemCertBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: b,
	})
	pemKeyBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(p)})
	cert, err := tls.X509KeyPair(pemCertBytes, pemKeyBytes)
	if err != nil {
		t.Fatalf("error creating listener cert: %v", err)
	}
	config := tls.Config{Certificates: []tls.Certificate{cert}}
	config.Rand = rand.Reader
	service := "0.0.0.0:8000"
	listener, err := tls.Listen("tcp", service, &config)
	if err != nil {
		t.Fatalf("error creating listener: %v", err)
	}
	for {
		connIn, err := listener.Accept()
		if err != nil {
			t.Logf("server: accept: %s", err)
			break
		}
		connOut, err := dialTCP(c)
		if err != nil {
			t.Fatalf("error creating downstream connection: %v", err)
		}
		//defer connIn.Close()
		//defer connOut.Close()
		t.Logf("server: accepted from %s", connIn.RemoteAddr())
		tlscon, ok := connIn.(*tls.Conn)
		if ok {
			t.Logf("ok=true")
			state := tlscon.ConnectionState()
			for _, v := range state.PeerCertificates {
				t.Log(x509.MarshalPKIXPublicKey(v.PublicKey))
			}
		}
		go proxyTraffic(connIn, connOut)
	}
}

// GenerateSelfSignedTLSKeyPairData generates a self signed key pair for testing use.
func GenerateSelfSignedTLSKeyPairData(t *testing.T) ([]byte, *rsa.PrivateKey) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	notBefore := time.Now()
	notAfter := notBefore.Add(time.Hour * 2 * 365 * 24)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	template.IPAddresses = append(template.IPAddresses, net.ParseIP("127.0.0.1"))
	template.DNSNames = append(template.DNSNames, "localhost")
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Errorf("Error creating certifcate for testing: %v", err)
	}
	return derBytes, priv
}
