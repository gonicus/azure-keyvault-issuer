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

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	azurekeyvaultissuerv1alpha1 "github.com/joshmue/azure-keyvault-issuer/api/v1alpha1"
)

type HealthChecker interface {
	Check() error
}

type HealthCheckerBuilder func(*azurekeyvaultissuerv1alpha1.IssuerSpec, *azurekeyvaultissuerv1alpha1.IssuerStatus) (HealthChecker, error)

type Signer interface {
	SignCSR(context.Context, []byte) ([]byte, error)
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
		publicKey: rsa.PublicKey{
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
	publicKey  crypto.PublicKey
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

func (o *azureKeyvaultSigner) SignCSR(ctx context.Context, csrBytes []byte) ([]byte, error) {
	csrPemBlock, _ := pem.Decode(csrBytes)
	csr, err := x509.ParseCertificateRequest(csrPemBlock.Bytes)
	if err != nil {
		return nil, err
	}

	parentPemBlock, _ := pem.Decode(o.parentCert)
	parentCert, err := x509.ParseCertificate(parentPemBlock.Bytes)
	if err != nil {
		return nil, err
	}

	if csr.PublicKeyAlgorithm != x509.RSA {
		return nil, fmt.Errorf("unsupported public key algorithm %v", csr.PublicKeyAlgorithm)
	}

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
		SerialNumber:       big.NewInt(1),
	}

	return x509.CreateCertificate(rand.Reader, &templateCertificate, parentCert, csr.PublicKey, o)
}
