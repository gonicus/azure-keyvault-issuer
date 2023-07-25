package signer

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	pkiutil "github.com/cert-manager/cert-manager/pkg/util/pki"
	azurekeyvaultissuerv1alpha1 "github.com/joshmue/azure-keyvault-issuer/api/v1alpha1"
)

type HealthChecker interface {
	Check() error
}

type HealthCheckerBuilder func(*azurekeyvaultissuerv1alpha1.IssuerSpec, *azurekeyvaultissuerv1alpha1.IssuerStatus) (HealthChecker, error)

type Signer interface {
	SignCSR(context.Context, []byte, []cmapi.KeyUsage, time.Duration) ([]byte, error)
}

type SignerBuilder func(context.Context, *azurekeyvaultissuerv1alpha1.IssuerSpec, *azurekeyvaultissuerv1alpha1.IssuerStatus) (Signer, error)

func AzureKeyvaultHealthCheckerFromIssuerAndSecretData(context.Context, *azurekeyvaultissuerv1alpha1.IssuerSpec, *azurekeyvaultissuerv1alpha1.IssuerStatus) (HealthChecker, error) {
	return &azureKeyvaultSigner{}, nil
}

func AzureKeyvaultSignerFromIssuerAndSecretData(ctx context.Context, issuerSpec *azurekeyvaultissuerv1alpha1.IssuerSpec, issuerStatus *azurekeyvaultissuerv1alpha1.IssuerStatus) (Signer, error) {
	creds, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, err
	}
	client, err := azkeys.NewClient(issuerSpec.KeyVaultBaseURL, creds, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.GetKey(ctx, issuerSpec.KeyName, issuerSpec.KeyVersion, nil)
	if err != nil {
		return nil, err
	}
	if *resp.Key.Kty != azkeys.KeyTypeRSA {
		return nil, errors.New("unsupported key type kty")
	}

	return &azureKeyvaultSigner{
		client: client,
		publicKey: &rsa.PublicKey{
			N: big.NewInt(0).SetBytes(resp.Key.N),
			E: int(big.NewInt(0).SetBytes(resp.Key.E).Int64()),
		},
		keyName:    issuerSpec.KeyName,
		keyVersion: issuerSpec.KeyVersion,
		parentCert: issuerStatus.CACertificate,
	}, nil
}

type azureKeyvaultSigner struct {
	client     *azkeys.Client
	publicKey  *rsa.PublicKey
	keyName    string
	keyVersion string
	parentCert []byte
}

func (o *azureKeyvaultSigner) Check() error {
	return nil
}

func (o *azureKeyvaultSigner) Public() crypto.PublicKey {
	return o.publicKey
}

func (o *azureKeyvaultSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	signAlgorithm := azkeys.SignatureAlgorithmRS512
	resp, err := o.client.Sign(context.Background(), o.keyName, o.keyVersion, azkeys.SignParameters{
		Algorithm: &signAlgorithm,
		Value:     digest,
	}, nil)
	return resp.KeyOperationResult.Result, err
}

func (o *azureKeyvaultSigner) SignCSR(ctx context.Context, csrBytes []byte, usages []cmapi.KeyUsage, duration time.Duration) ([]byte, error) {
	csrPemBlock, _ := pem.Decode(csrBytes)
	csr, err := x509.ParseCertificateRequest(csrPemBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("unable to decode CSR: %w", err)
	}

	parentPemBlock, _ := pem.Decode(o.parentCert)
	parentCert, err := x509.ParseCertificate(parentPemBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("unable to decode parent certficate: %w", err)
	}

	if csr.PublicKeyAlgorithm != x509.RSA {
		return nil, fmt.Errorf("unsupported public key algorithm %v", csr.PublicKeyAlgorithm)
	}

	x509KeyUsage, x509ExtKeyUsages, err := pkiutil.KeyUsagesForCertificateOrCertificateRequest(usages, false)
	if err != nil {
		return nil, fmt.Errorf("unable to extract key usages: %w", err)
	}

	now := time.Now()

	templateCertificate := x509.Certificate{
		SignatureAlgorithm: x509.SHA512WithRSA,
		PublicKeyAlgorithm: csr.PublicKeyAlgorithm,
		PublicKey:          csr.PublicKey,
		Version:            csr.Version,
		Subject:            csr.Subject,
		Extensions:         csr.Extensions,
		ExtraExtensions:    csr.ExtraExtensions,
		DNSNames:           csr.DNSNames,
		EmailAddresses:     csr.EmailAddresses,
		IPAddresses:        csr.IPAddresses,
		URIs:               csr.URIs,
		KeyUsage:           x509KeyUsage,
		ExtKeyUsage:        x509ExtKeyUsages,
		NotBefore:          now.Add(-time.Minute),
		NotAfter:           now.Add(duration),
		SerialNumber:       big.NewInt(1),
	}

	result, err := x509.CreateCertificate(rand.Reader, &templateCertificate, parentCert, csr.PublicKey, o)
	if err != nil {
		return nil, fmt.Errorf("unable to create certificate: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: result,
	}), nil
}
