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

	cmutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/utils/clock"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	azurekeyvaultissuerv1alpha1 "github.com/joshmue/azure-keyvault-issuer/api/v1alpha1"
	"github.com/joshmue/azure-keyvault-issuer/internal/issuer/signer"
	issuerutil "github.com/joshmue/azure-keyvault-issuer/internal/issuer/util"
)

var (
	errIssuerRef      = errors.New("error interpreting issuerRef")
	errGetIssuer      = errors.New("error getting issuer")
	errIssuerNotReady = errors.New("issuer is not ready")
	errSignerBuilder  = errors.New("failed to build the signer")
	errSignerSign     = errors.New("failed to sign")
)

// CertificateRequestReconciler reconciles a CertificateRequest object
type CertificateRequestReconciler struct {
	client.Client
	Scheme        *runtime.Scheme
	Clock         clock.Clock
	SignerBuilder signer.SignerBuilder
}

//+kubebuilder:rbac:groups=cert-manager.io,resources=certificaterequests,verbs=get;list;watch
//+kubebuilder:rbac:groups=cert-manager.io,resources=certificaterequests/status,verbs=get;update;patch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the CertificateRequest object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.15.0/pkg/reconcile
func (r *CertificateRequestReconciler) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, err error) {
	log := log.FromContext(ctx)

	var certificateRequest cmapi.CertificateRequest
	if err := r.Get(ctx, req.NamespacedName, &certificateRequest); err != nil {
		if err := client.IgnoreNotFound(err); err != nil {
			return ctrl.Result{}, fmt.Errorf("unexpected get error: %w", err)
		}
		log.Info("Not found. Ignoring.")
		return ctrl.Result{}, nil
	}

	// Ignore CertificateRequest if issuerRef doesn't match our group
	if certificateRequest.Spec.IssuerRef.Group != azurekeyvaultissuerv1alpha1.GroupVersion.Group {
		log.Info("Foreign group. Ignoring.", "group", certificateRequest.Spec.IssuerRef.Group)
		return ctrl.Result{}, nil
	}

	// Ignore CertificateRequest if it is already Ready
	if cmutil.CertificateRequestHasCondition(&certificateRequest, cmapi.CertificateRequestCondition{
		Type:   cmapi.CertificateRequestConditionReady,
		Status: cmmeta.ConditionTrue,
	}) {
		log.Info("CertificateRequest is Ready. Ignoring.")
		return ctrl.Result{}, nil
	}
	// Ignore CertificateRequest if it is already Failed
	if cmutil.CertificateRequestHasCondition(&certificateRequest, cmapi.CertificateRequestCondition{
		Type:   cmapi.CertificateRequestConditionReady,
		Status: cmmeta.ConditionFalse,
		Reason: cmapi.CertificateRequestReasonFailed,
	}) {
		log.Info("CertificateRequest is Failed. Ignoring.")
		return ctrl.Result{}, nil
	}
	// Ignore CertificateRequest if it already has a Denied Ready Reason
	if cmutil.CertificateRequestHasCondition(&certificateRequest, cmapi.CertificateRequestCondition{
		Type:   cmapi.CertificateRequestConditionReady,
		Status: cmmeta.ConditionFalse,
		Reason: cmapi.CertificateRequestReasonDenied,
	}) {
		log.Info("CertificateRequest already has a Ready condition with Denied Reason. Ignoring.")
		return ctrl.Result{}, nil
	}

	// If CertificateRequest has not been approved, exit early.
	if !cmutil.CertificateRequestIsApproved(&certificateRequest) {
		log.Info("CertificateRequest has not been approved yet. Ignoring.")
		return ctrl.Result{}, nil
	}

	// report gives feedback by updating the Ready Condition of the Certificate Request.
	// For added visibility we also log a message and create a Kubernetes Event.
	report := func(reason, message string, err error) {
		status := cmmeta.ConditionFalse
		if reason == cmapi.CertificateRequestReasonIssued {
			status = cmmeta.ConditionTrue
		}
		if err != nil {
			log.Error(err, message)
			message = fmt.Sprintf("%s: %v", message, err)
		} else {
			log.Info(message)
		}
		cmutil.SetCertificateRequestCondition(
			&certificateRequest,
			cmapi.CertificateRequestConditionReady,
			status,
			reason,
			message,
		)
	}

	// Always attempt to update the Ready condition
	defer func() {
		if err != nil {
			report(cmapi.CertificateRequestReasonPending, "Temporary error. Retrying", err)
		}
		if updateErr := r.Status().Update(ctx, &certificateRequest); updateErr != nil {
			err = utilerrors.NewAggregate([]error{err, updateErr})
			result = ctrl.Result{}
		}
	}()

	// If CertificateRequest has been denied, mark the CertificateRequest as
	// Ready=Denied and set FailureTime if not already.
	if cmutil.CertificateRequestIsDenied(&certificateRequest) {
		log.Info("CertificateRequest has been denied yet. Marking as failed.")

		if certificateRequest.Status.FailureTime == nil {
			nowTime := metav1.NewTime(r.Clock.Now())
			certificateRequest.Status.FailureTime = &nowTime
		}

		message := "The CertificateRequest was denied by an approval controller"
		report(cmapi.CertificateRequestReasonDenied, message, nil)
		return ctrl.Result{}, nil
	}

	// Add a Ready condition if one does not already exist
	if ready := cmutil.GetCertificateRequestCondition(&certificateRequest, cmapi.CertificateRequestConditionReady); ready == nil {
		report(cmapi.CertificateRequestReasonPending, "Initialising Ready condition", nil)
		return ctrl.Result{}, nil
	}

	// Ignore but log an error if the issuerRef.Kind is unrecognised
	issuerGVK := azurekeyvaultissuerv1alpha1.GroupVersion.WithKind(certificateRequest.Spec.IssuerRef.Kind)
	issuerRO, err := r.Scheme.New(issuerGVK)
	if err != nil {
		report(cmapi.CertificateRequestReasonFailed, "Unrecognised kind. Ignoring", fmt.Errorf("%w: %v", errIssuerRef, err))
		return ctrl.Result{}, nil
	}
	issuer := issuerRO.(client.Object)
	// Create a Namespaced name for Issuer and a non-Namespaced name for ClusterIssuer
	issuerName := types.NamespacedName{
		Name: certificateRequest.Spec.IssuerRef.Name,
	}
	if _, isNamespaced := issuer.(*azurekeyvaultissuerv1alpha1.Issuer); isNamespaced {
		issuerName.Namespace = certificateRequest.Namespace
	}

	// Get the Issuer or ClusterIssuer
	if err := r.Get(ctx, issuerName, issuer); err != nil {
		return ctrl.Result{}, fmt.Errorf("%w: %v", errGetIssuer, err)
	}

	var issuerSpec *azurekeyvaultissuerv1alpha1.IssuerSpec
	switch issuerImp := issuer.(type) {
	case *azurekeyvaultissuerv1alpha1.ClusterIssuer:
		issuerSpec = &issuerImp.Spec
	case *azurekeyvaultissuerv1alpha1.Issuer:
		issuerSpec = &issuerImp.Spec
	default:
		return ctrl.Result{}, errIssuerRef
	}

	var issuerStatus *azurekeyvaultissuerv1alpha1.IssuerStatus
	switch issuerImp := issuer.(type) {
	case *azurekeyvaultissuerv1alpha1.ClusterIssuer:
		issuerStatus = &issuerImp.Status
	case *azurekeyvaultissuerv1alpha1.Issuer:
		issuerStatus = &issuerImp.Status
	default:
		return ctrl.Result{}, errIssuerRef
	}

	issuerCondition := issuerutil.GetReadyCondition(issuerStatus)
	if issuerCondition == nil || issuerCondition.Status != cmmeta.ConditionTrue {
		return ctrl.Result{}, fmt.Errorf("%w: status is %v", errIssuerNotReady, issuerCondition)
	}

	signer, err := r.SignerBuilder(ctx, issuerSpec, issuerStatus)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("%w: %v", errSignerBuilder, err)
	}

	duration := time.Hour
	if certificateRequest.Spec.Duration != nil {
		duration = certificateRequest.Spec.Duration.Duration
	}

	signed, err := signer.SignCSR(ctx, certificateRequest.Spec.Request, certificateRequest.Spec.Usages, duration)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("%w: %v", errSignerSign, err)
	}
	certificateRequest.Status.Certificate = signed

	report(cmapi.CertificateRequestReasonIssued, "Signed", nil)
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *CertificateRequestReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&cmapi.CertificateRequest{}).
		Complete(r)
}
