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

package controller

import (
	"context"
	"errors"
	"fmt"
	"time"

	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	azurekeyvaultissuerv1alpha1 "github.com/gonicus/azure-keyvault-issuer/api/v1alpha1"
	cahandler "github.com/gonicus/azure-keyvault-issuer/internal/issuer/ca_handler"
	issuerutil "github.com/gonicus/azure-keyvault-issuer/internal/issuer/util"
)

var (
	errCAHandlerBuilder = errors.New("could not create ca handler")
	errCAFetch          = errors.New("could not fetch ca")
)

// IssuerReconciler reconciles a Issuer object
type IssuerReconciler struct {
	client.Client
	Kind             string
	Scheme           *runtime.Scheme
	CAHandlerBuilder cahandler.CAHandlerBuilder
}

//+kubebuilder:rbac:groups=azure-keyvault-issuer.gonicus.de,resources=issuers,verbs=get;list;watch
//+kubebuilder:rbac:groups=azure-keyvault-issuer.gonicus.de,resources=issuers/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=azure-keyvault-issuer.gonicus.de,resources=clusterissuers,verbs=get;list;watch
//+kubebuilder:rbac:groups=azure-keyvault-issuer.gonicus.de,resources=clusterissuers/status,verbs=get;update;patch

func (r *IssuerReconciler) newIssuer() (client.Object, error) {
	issuerGVK := azurekeyvaultissuerv1alpha1.GroupVersion.WithKind(r.Kind)
	ro, err := r.Scheme.New(issuerGVK)
	if err != nil {
		return nil, err
	}
	return ro.(client.Object), nil
}

func (r *IssuerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, err error) {
	log := ctrl.LoggerFrom(ctx)

	issuer, err := r.newIssuer()
	if err != nil {
		log.Error(err, "Unrecognised issuer type")
		return ctrl.Result{}, nil
	}
	if err := r.Get(ctx, req.NamespacedName, issuer); err != nil {
		if err := client.IgnoreNotFound(err); err != nil {
			return ctrl.Result{}, fmt.Errorf("unexpected get error: %v", err)
		}
		log.Info("Not found. Ignoring.")
		return ctrl.Result{}, nil
	}

	issuerSpec, issuerStatus, err := issuerutil.GetSpecAndStatus(issuer)
	if err != nil {
		log.Error(err, "Unexpected error while getting issuer spec and status. Not retrying.")
		return ctrl.Result{}, nil
	}

	// report gives feedback by updating the Ready Condition of the {Cluster}Issuer
	// For added visibility we also log a message and create a Kubernetes Event.
	report := func(conditionStatus cmmeta.ConditionStatus, message string, err error) {
		if err != nil {
			log.Error(err, message)
			message = fmt.Sprintf("%s: %v", message, err)
		} else {
			log.Info(message)
		}
		issuerutil.SetReadyCondition(issuerStatus, conditionStatus, "IssuerReconciler", message)
	}

	// Always attempt to update the Ready condition
	defer func() {
		if err != nil {
			report(cmmeta.ConditionFalse, "Temporary error. Retrying", err)
		}
		if updateErr := r.Status().Update(ctx, issuer); updateErr != nil {
			err = utilerrors.NewAggregate([]error{err, updateErr})
			result = ctrl.Result{}
		}
	}()

	if ready := issuerutil.GetReadyCondition(issuerStatus); ready == nil {
		report(cmmeta.ConditionUnknown, "First seen", nil)
		return ctrl.Result{}, nil
	}

	caHandler, err := r.CAHandlerBuilder(ctx, issuerSpec, issuerStatus)
	if err != nil {
		log.Error(err, "")
		issuerutil.SetReadyCondition(issuerStatus, cmmeta.ConditionFalse, "Failure", errCAHandlerBuilder.Error())
		return ctrl.Result{}, fmt.Errorf("%w: %v", errCAHandlerBuilder, err)
	}

	certPemBytes, err := caHandler.FetchCACertificate(ctx)
	if err != nil {
		log.Error(err, "")
		issuerutil.SetReadyCondition(issuerStatus, cmmeta.ConditionFalse, "Failure", errCAFetch.Error())
		return ctrl.Result{}, fmt.Errorf("%w: %v", errCAFetch, err)
	}

	issuerStatus.CACertificate = certPemBytes
	report(cmmeta.ConditionTrue, "Success", nil)
	return ctrl.Result{RequeueAfter: time.Minute}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *IssuerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&azurekeyvaultissuerv1alpha1.Issuer{}).
		Complete(r)
}
