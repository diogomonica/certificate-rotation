package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"sync"
	"time"
)

type wrappedCertificate struct {
	sync.Mutex
	certificate *tls.Certificate
}

func (c *wrappedCertificate) getCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	c.Lock()
	defer c.Unlock()

	return c.certificate, nil
}

func (c *wrappedCertificate) loadCertificate(cert, key []byte) error {
	c.Lock()
	defer c.Unlock()

	certAndKey, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return err
	}

	c.certificate = &certAndKey

	return nil
}

func generateNewCert() ([]byte, []byte, error) {
	randOrg := make([]byte, 32)
	_, err := rand.Read(randOrg)
	template := &x509.Certificate{
		IsCA: true,
		BasicConstraintsValid: true,
		SubjectKeyId:          []byte{1},
		SerialNumber:          big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{base64.URLEncoding.EncodeToString(randOrg)},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(5, 5, 5),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	privatekey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	publickey := &privatekey.PublicKey
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, publickey, privatekey)

	return pem.EncodeToMemory(&pem.Block{
			Type: "CERTIFICATE", Bytes: certDER}),
		pem.EncodeToMemory(&pem.Block{
			Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privatekey)}),
		err
}

func main() {
	wrappedCert := &wrappedCertificate{}
	config := &tls.Config{
		GetCertificate:           wrappedCert.getCertificate,
		PreferServerCipherSuites: true,
		MinVersion:               tls.VersionTLS10,
	}
	network := "0.0.0.0:8080"
	listener, err := tls.Listen("tcp", network, config)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				fmt.Printf("Generating new certificates.\n")
				cert, key, err := generateNewCert()
				if err != nil {
					fmt.Printf("error when generating new cert: %v", err)
					continue
				}
				err = wrappedCert.loadCertificate(cert, key)
				if err != nil {
					fmt.Printf("error when loading cert: %v", err)
				}
			case <-done:
				return
			}
		}
	}()
	defer close(done)

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println(err.Error())
			continue
		}
		fmt.Fprintf(conn, "Hello over TLS\n")
		conn.Close()
	}
}
