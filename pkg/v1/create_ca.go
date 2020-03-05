package v1

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"os"
	"time"
)

// pkix.Name{
// 	Organization:  []string{"ORGANIZATION_NAME"},
// 	Country:       []string{"COUNTRY_CODE"},
// 	Province:      []string{"PROVINCE"},
// 	Locality:      []string{"CITY"},
// 	StreetAddress: []string{"ADDRESS"},
// 	PostalCode:    []string{"POSTAL_CODE"},
// },

// CreateCA ...
func CreateCA(path string, name string, subject pkix.Name) {

	ca := &x509.Certificate{
		SerialNumber:          big.NewInt(1653),
		Subject:               subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		DNSNames: []string{
			"test.com",
		},
	}

	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	pub := &priv.PublicKey
	cab, err := x509.CreateCertificate(rand.Reader, ca, ca, pub, priv)
	if err != nil {
		log.Println("create ca failed", err)
		return
	}

	// Public key
	certOut, err := os.Create(path + "/" + name + ".pem")
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: cab})
	certOut.Close()
	log.Print("written cert.pem\n")

	// Private key
	keyOut, err := os.OpenFile(path+"/"+name+".key", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	keyOut.Close()
	log.Print("written key.pem\n")

}
