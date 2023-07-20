/*
Copyright 2020 The cert-manager Authors

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

package util

import (
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"

	azurekeyvaultissuerv1alpha1 "github.com/joshmue/azure-keyvault-issuer/api/v1alpha1"
)

func GetSpecAndStatus(issuer client.Object) (*azurekeyvaultissuerv1alpha1.IssuerSpec, *azurekeyvaultissuerv1alpha1.IssuerStatus, error) {
	switch t := issuer.(type) {
	case *azurekeyvaultissuerv1alpha1.Issuer:
		return &t.Spec, &t.Status, nil
	case *azurekeyvaultissuerv1alpha1.ClusterIssuer:
		return &t.Spec, &t.Status, nil
	default:
		return nil, nil, fmt.Errorf("not an issuer type: %t", t)
	}
}

func SetReadyCondition(status *azurekeyvaultissuerv1alpha1.IssuerStatus, conditionStatus cmmeta.ConditionStatus, reason, message string) {
	ready := GetReadyCondition(status)
	if ready == nil {
		ready = &cmapi.IssuerCondition{
			Type: cmapi.IssuerConditionReady,
		}
		status.Conditions = append(status.Conditions, *ready)
	}
	if ready.Status != conditionStatus {
		ready.Status = conditionStatus
		now := metav1.Now()
		ready.LastTransitionTime = &now
	}
	ready.Reason = reason
	ready.Message = message

	for i, c := range status.Conditions {
		if c.Type == cmapi.IssuerConditionReady {
			status.Conditions[i] = *ready
			return
		}
	}
}

func GetReadyCondition(status *azurekeyvaultissuerv1alpha1.IssuerStatus) *cmapi.IssuerCondition {
	for _, c := range status.Conditions {
		if c.Type == cmapi.IssuerConditionReady {
			return &c
		}
	}
	return nil
}

func IsReady(status *azurekeyvaultissuerv1alpha1.IssuerStatus) bool {
	if c := GetReadyCondition(status); c != nil {
		return c.Status == cmmeta.ConditionTrue
	}
	return false
}