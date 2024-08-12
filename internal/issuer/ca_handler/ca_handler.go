package cahandler

import (
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	azurekeyvaultissuerv1alpha1 "github.com/gonicus/azure-keyvault-issuer/api/v1alpha1"
)

type HealthChecker interface {
	Check() error
}

type HealthCheckerBuilder func(*azurekeyvaultissuerv1alpha1.IssuerSpec, *azurekeyvaultissuerv1alpha1.IssuerStatus) (HealthChecker, error)

type CAHandler interface {
	FetchCACertificate(context.Context) ([]byte, error)
}

type CAHandlerBuilder func(context.Context, *azurekeyvaultissuerv1alpha1.IssuerSpec, *azurekeyvaultissuerv1alpha1.IssuerStatus) (CAHandler, error)

func AzureKeyvaultHealthCheckerFromIssuerAndSecretData(context.Context, *azurekeyvaultissuerv1alpha1.IssuerSpec, *azurekeyvaultissuerv1alpha1.IssuerStatus) (HealthChecker, error) {
	return &azureKeyvaultCAHandler{}, nil
}

func AzureKeyvaultCAHandlerFromIssuerAndSecretData(ctx context.Context, issuerSpec *azurekeyvaultissuerv1alpha1.IssuerSpec, issuerStatus *azurekeyvaultissuerv1alpha1.IssuerStatus) (CAHandler, error) {
	creds, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, err
	}
	client, err := azsecrets.NewClient(issuerSpec.KeyVaultBaseURL, creds, nil)
	if err != nil {
		return nil, err
	}

	return &azureKeyvaultCAHandler{
		client:     client,
		secretName: issuerSpec.KeyName,
	}, nil
}

type azureKeyvaultCAHandler struct {
	client     *azsecrets.Client
	secretName string
}

func (o *azureKeyvaultCAHandler) FetchCACertificate(ctx context.Context) ([]byte, error) {
	resp, err := o.client.GetSecret(ctx, o.secretName, "", nil)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch CA certificate from azure keyvault: %w", err)
	}
	if resp.Value == nil {
		return nil, fmt.Errorf("got empty value while fetching CA certificate from azure keyvault")
	}
	return []byte(*resp.Value), nil
}

func (o *azureKeyvaultCAHandler) Check() error {
	return nil
}
