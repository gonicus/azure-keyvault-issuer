package controller

import (
	"context"
	"errors"
	"fmt"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	azurekeyvaultissuerv1alpha1 "github.com/joshmue/azure-keyvault-issuer/api/v1alpha1"
	cahandler "github.com/joshmue/azure-keyvault-issuer/internal/issuer/ca_handler"
)

var (
	errCAHandlerBuilder = errors.New("could not create ca handler")
	errCAFetch          = errors.New("could not fetch ca")
)

// Borrowed from sample-external-issuer
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

// Borrowed from sample-external-issuer
func GetReadyCondition(status *azurekeyvaultissuerv1alpha1.IssuerStatus) *cmapi.IssuerCondition {
	for _, c := range status.Conditions {
		if c.Type == cmapi.IssuerConditionReady {
			return &c
		}
	}
	return nil
}

func ReconcileIssuerOrClusterIssuer(ctx context.Context, req ctrl.Request, clientImpl client.Client, scheme *runtime.Scheme, caHandlerBuilder cahandler.CAHandlerBuilder) (ctrl.Result, error) {
	log := log.FromContext(ctx)
	// TODO handle difference between Issuer and ClusterIssuer?
	var issuer azurekeyvaultissuerv1alpha1.Issuer
	if err := clientImpl.Get(ctx, req.NamespacedName, &issuer); err != nil {
		if err := client.IgnoreNotFound(err); err != nil {
			return ctrl.Result{}, fmt.Errorf("unexpected get error: %w", err)
		}
		log.Info("Not found. Ignoring.")
		return ctrl.Result{}, nil
	}

	caHandler, err := caHandlerBuilder(ctx, &issuer.Spec, &issuer.Status)
	if err != nil {
		log.Error(err, "")
		SetReadyCondition(&issuer.Status, cmmeta.ConditionFalse, "Failure", errCAHandlerBuilder.Error())
		return ctrl.Result{}, fmt.Errorf("%w: %v", errCAHandlerBuilder, err)
	}

	certPemBytes, err := caHandler.FetchCACertificate(ctx)
	if err != nil {
		log.Error(err, "")
		SetReadyCondition(&issuer.Status, cmmeta.ConditionFalse, "Failure", errCAFetch.Error())
		return ctrl.Result{}, fmt.Errorf("%w: %v", errCAFetch, err)
	}

	issuer.Status.CACertificate = certPemBytes

	SetReadyCondition(&issuer.Status, cmmeta.ConditionTrue, "Success", "ca fetch worked")
	err = clientImpl.Status().Update(ctx, &issuer)
	if err != nil {
		log.Error(err, "")
		return ctrl.Result{}, fmt.Errorf("could not save status: %w", err)
	}

	return ctrl.Result{RequeueAfter: time.Minute}, nil
}
