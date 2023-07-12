package signer

import (
	azurekeyvaultissuerv1alpha1 "github.com/joshmue/azure-keyvault-issuer/api/v1alpha1"
)

type HealthChecker interface {
	Check() error
}

type HealthCheckerBuilder func(*azurekeyvaultissuerv1alpha1.IssuerSpec) (HealthChecker, error)

type Signer interface {
	Sign([]byte) ([]byte, error)
}

type SignerBuilder func(*azurekeyvaultissuerv1alpha1.IssuerSpec) (Signer, error)

func AzureKeyvaultHealthCheckerFromIssuerAndSecretData(*azurekeyvaultissuerv1alpha1.IssuerSpec) (HealthChecker, error) {
	return &azureKeyvaultSigner{}, nil
}

func AzureKeyvaultSignerFromIssuerAndSecretData(*azurekeyvaultissuerv1alpha1.IssuerSpec) (Signer, error) {
	return &azureKeyvaultSigner{}, nil
}

type azureKeyvaultSigner struct {
}

func (o *azureKeyvaultSigner) Check() error {
	return nil
}

func (o *azureKeyvaultSigner) Sign(csrBytes []byte) ([]byte, error) {
	return []byte("a result!"), nil
}
