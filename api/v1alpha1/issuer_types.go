/*
Copyright 2023 The azure-keyvault-issuer Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// IssuerSpec defines the desired state of Issuer
type IssuerSpec struct {
	// KeyVaultBaseURL is the https URL to the Key Vault
	KeyVaultBaseURL string `json:"keyVaultBaseURL"`
	// KeyName is the "name" of the "Key" resource
	KeyName string `json:"keyName"`
	// KeyVersion is the "version" of the "Key" resource
	KeyVersion string `json:"keyVersion"`
	// ParentCert is usually the CA certificate
	ParentCert []byte `json:"parentCert"`
}

// IssuerStatus defines the observed state of Issuer
type IssuerStatus struct{}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// Issuer is the Schema for the issuers API
type Issuer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   IssuerSpec   `json:"spec,omitempty"`
	Status IssuerStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// IssuerList contains a list of Issuer
type IssuerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Issuer `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Issuer{}, &IssuerList{})
}
