package v1

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
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
// }

// CreateCert ...
func CreateCert(certPath string, certName string, CApath string, CAname string, subject pkix.Name) {

	// TODO: check if extension is already passed to the function
	// Load CA
	catls, err := tls.LoadX509KeyPair(CApath+"/"+CAname+".pem", CApath+"/"+CAname+".key")
	if err != nil {
		panic(err)
	}
	ca, err := x509.ParseCertificate(catls.Certificate[0])
	if err != nil {
		panic(err)
	}

	// Prepare certificate
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1658),
		Subject:      subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		DNSNames: []string{
			"test.com",
		},
	}
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	pub := &priv.PublicKey

	// Sign the certificate
	certb, err := x509.CreateCertificate(rand.Reader, cert, ca, pub, catls.PrivateKey)

	// Public key
	certOut, err := os.Create(certPath + "/" + certName + ".pem")
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certb})
	certOut.Close()
	log.Print("written cert.pem\n")

	// Private key
	keyOut, err := os.OpenFile(certPath+"/"+certName+".key", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	keyOut.Close()
	log.Print("written key.pem\n")

}
