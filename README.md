# azure-keyvault-issuer

`azure-keyvault-issuer` is a [external issuer](https://cert-manager.io/docs/configuration/external/) for cert-manager, using an Azure Keyvault "Key" to sign `CertificateRequests`.

## Workflow

Participants:

- `hack/create_ca_cert`: Go command line tool in `hack/create_ca_cert`
- `ProvisioningTooling`: Tooling like `az` or `terraform`
- `azure-keyvault-issuer`: Kubernetes Controller
- `IssuerCR`: Custom Resource (instance, not definition) of azure-keyvault-issuer `Issuer`
- `CertificateRequestCR`: Custom Resource (instance, not definition) of cert-manager `CertificateRequest`

```mermaid
sequenceDiagram
participant ProvisioningTooling
participant hack/create_ca_cert
participant AzureKeyVaultKey
participant AzureKeyVaultSecret
participant azure-keyvault-issuer
participant IssuerCR
participant CertificateRequestCR
ProvisioningTooling->>AzureKeyVaultKey: Create (RSA)
hack/create_ca_cert->>hack/create_ca_cert: Setup CA certificate template
hack/create_ca_cert->>AzureKeyVaultKey: Build CA certificate using sign operation
hack/create_ca_cert->>AzureKeyVaultSecret: Store CA certificate
loop Issuer reconcile interval
    azure-keyvault-issuer->>AzureKeyVaultSecret: Fetch CA certificate
    azure-keyvault-issuer->>IssuerCR: Get
    azure-keyvault-issuer->>IssuerCR: Set Ready condition and CA certificate in status
end
loop CertificateRequest reconcile interval
    azure-keyvault-issuer->>CertificateRequestCR: Get
    azure-keyvault-issuer->>azure-keyvault-issuer: Verify CertificateRequest is suitable for signing
    azure-keyvault-issuer->>IssuerCR: Get
    azure-keyvault-issuer->>azure-keyvault-issuer: Configure AzureKeyVault client using IssuerCR spec
    azure-keyvault-issuer->>AzureKeyVaultKey: Build certificate using CA certificate from IssuerCR status and Sign operation
    azure-keyvault-issuer->>CertificateRequestCR: Set certificate in status
end


```
