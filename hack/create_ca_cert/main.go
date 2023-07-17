package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"io"
	"log"
	"math/big"
	"os"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
)

type Signer struct {
	client     *azkeys.Client
	publicKey  crypto.PublicKey
	keyName    string
	keyVersion string
}

func (o *Signer) Public() crypto.PublicKey {
	return o.publicKey
}

func (o *Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	signAlgorithm := azkeys.SignatureAlgorithmRS512
	resp, err := o.client.Sign(context.Background(), o.keyName, o.keyVersion, azkeys.SignParameters{
		Algorithm: &signAlgorithm,
		Value:     digest,
	}, nil)
	return resp.KeyOperationResult.Result, err
}

func main() {
	vaultBaseUrl := flag.String("vault.base-url", "", "Vault Base URL")
	vaultKeyName := flag.String("vault.key.name", "", "Vault Key Name")
	vaultKeyVersion := flag.String("vault.key.version", "", "Vault Key Version")
	certificateCN := flag.String("certificate.cn", "cert-manager-ca.invalid", "CN to set in the CA certificate")
	certificateLifetime := flag.Duration("certificate.lifetime", time.Hour*24*365*10, "Lifetime of CA certificate")
	flag.Parse()

	if *vaultBaseUrl == "" || *vaultKeyName == "" || *vaultKeyVersion == "" {
		log.Fatal("missing vault flag")
	}

	creds, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatal(err)
	}
	client, err := azkeys.NewClient(*vaultBaseUrl, creds, nil)
	if err != nil {
		log.Fatal(err)
	}

	keyResp, err := client.GetKey(context.Background(), *vaultKeyName, *vaultKeyVersion, nil)
	if err != nil {
		log.Fatal(err)
	}
	if *keyResp.Key.Kty != azkeys.KeyTypeRSA {
		log.Fatal("unsupported key type kty")
	}
	publicKey := &rsa.PublicKey{
		N: big.NewInt(0).SetBytes(keyResp.Key.N),
		E: int(big.NewInt(0).SetBytes(keyResp.Key.E).Int64()),
	}

	certificateTemplate := &x509.Certificate{
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(*certificateLifetime),
		SerialNumber:          big.NewInt(1),
		SignatureAlgorithm:    x509.SHA512WithRSA,
		Subject: pkix.Name{
			CommonName: *certificateCN,
		},
	}

	signer := &Signer{
		client:     client,
		publicKey:  publicKey,
		keyName:    *vaultKeyName,
		keyVersion: *vaultKeyVersion,
	}

	result, err := x509.CreateCertificate(rand.Reader, certificateTemplate, certificateTemplate, publicKey, signer)
	if err != nil {
		log.Fatal(err)
	}
	err = pem.Encode(os.Stdout, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: result,
	})
	if err != nil {
		log.Fatal(err)
	}
}
