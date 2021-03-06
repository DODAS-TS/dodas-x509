package main

import (
	"crypto/x509/pkix"
	"flag"

	v1 "github.com/dodas-ts/dodas-x509/pkg/v1"
)

var (
	genCA   bool
	genCert bool
	genAll  bool

	hostname string
	certName string
	caName   string
	caPath   string
	certPath string
)

func init() {
	flag.BoolVar(&genCA, "generate-ca", false, "Generate only CA certs")
	flag.BoolVar(&genCert, "generate-cert", false, "Generate certs starting from existing CA")
	flag.BoolVar(&genAll, "generate-all", true, "Generate both CA and host certs")

	flag.StringVar(&hostname, "hostname", "localhost", "Hostname to be on cert CN")
	flag.StringVar(&certName, "cert-name", "hostcert", "certificates filename")
	flag.StringVar(&caName, "ca-name", "myCa", "CA filename")
	flag.StringVar(&caPath, "ca-path", "/tmp", "Folder were CA certificates will be created")
	flag.StringVar(&certPath, "cert-path", "/tmp", "Folder were host certificates will be created")
	//flag.IntVar(&outputPath, "output-path", 120, "Proxy refresh period in minutes")

}

func main() {

	flag.Parse()

	sub := pkix.Name{
		Organization: []string{"DODAS"},
		Country:      []string{"IT"},
		CommonName:   hostname,
	}

	subCA := pkix.Name{
		Organization: []string{"DODAS"},
		Country:      []string{"IT"},
	}

	if genCA || genCert {
		genAll = false
	}

	//fmt.Println(genCert)

	if genCA || genAll {
		v1.CreateCA(caPath, caName, subCA)
	}

	if genCert || genAll {
		v1.CreateCert(certPath, certName, caPath, caName, sub, hostname)
	}

}
