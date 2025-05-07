package signer

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	pkiutil "github.com/cert-manager/cert-manager/pkg/util/pki"
	azurekeyvaultissuerv1alpha1 "github.com/gonicus/azure-keyvault-issuer/api/v1alpha1"
)

type HealthChecker interface {
	Check() error
}

type HealthCheckerBuilder func(*azurekeyvaultissuerv1alpha1.IssuerSpec, *azurekeyvaultissuerv1alpha1.IssuerStatus) (HealthChecker, error)

type Signer interface {
	CreateSignedCertificateFrom(*cmapi.CertificateRequest) ([]byte, error)
}

type SignerBuilder func(context.Context, *azurekeyvaultissuerv1alpha1.IssuerSpec, *azurekeyvaultissuerv1alpha1.IssuerStatus) (Signer, error)

func AzureKeyvaultHealthCheckerFromIssuerAndSecretData(context.Context, *azurekeyvaultissuerv1alpha1.IssuerSpec, *azurekeyvaultissuerv1alpha1.IssuerStatus) (HealthChecker, error) {
	return &azureKeyvaultSigner{}, nil
}

func AzureKeyvaultSignerFromIssuerAndSecretData(ctx context.Context, issuerSpec *azurekeyvaultissuerv1alpha1.IssuerSpec, issuerStatus *azurekeyvaultissuerv1alpha1.IssuerStatus) (Signer, error) {
	creds, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize azure auth: %w", err)
	}
	client, err := azkeys.NewClient(issuerSpec.KeyVaultBaseURL, creds, nil)
	if err != nil {
		return nil, fmt.Errorf("unable to create azkeys client: %w", err)
	}
	resp, err := client.GetKey(ctx, issuerSpec.KeyName, issuerSpec.KeyVersion, nil)
	if err != nil {
		return nil, fmt.Errorf("unable to get public key: %w", err)
	}
	if *resp.Key.Kty != azkeys.KeyTypeRSA {
		return nil, fmt.Errorf("unsupported key type kty %v", *resp.Key.Kty)
	}

	caCertificatePemBlock, _ := pem.Decode(issuerStatus.CACertificate)
	caCertificate, err := x509.ParseCertificate(caCertificatePemBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("unable to decode ca certficate: %w", err)
	}

	return &azureKeyvaultSigner{
		client: client,
		publicKey: &rsa.PublicKey{
			N: big.NewInt(0).SetBytes(resp.Key.N),
			E: int(big.NewInt(0).SetBytes(resp.Key.E).Int64()),
		},
		keyName:       issuerSpec.KeyName,
		keyVersion:    issuerSpec.KeyVersion,
		caCertificate: caCertificate,
	}, nil
}

type azureKeyvaultSigner struct {
	client        *azkeys.Client
	publicKey     *rsa.PublicKey
	keyName       string
	keyVersion    string
	caCertificate *x509.Certificate
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

func (o *azureKeyvaultSigner) CreateSignedCertificateFrom(certificateRequest *cmapi.CertificateRequest) ([]byte, error) {
	templateCertificate, err := pkiutil.GenerateTemplateFromCertificateRequest(certificateRequest)
	if err != nil {
		return nil, fmt.Errorf("unable to generate template for certficate: %w", err)
	}

	// Is this really necessary?
	if templateCertificate.PublicKeyAlgorithm != x509.RSA {
		return nil, fmt.Errorf("unsupported public key algorithm %v", templateCertificate.PublicKeyAlgorithm)
	}
	templateCertificate.SignatureAlgorithm = x509.SHA512WithRSA

	pemBytes, _, err := pkiutil.SignCertificate(templateCertificate, o.caCertificate, templateCertificate.PublicKey, o)
	return pemBytes, err
}
