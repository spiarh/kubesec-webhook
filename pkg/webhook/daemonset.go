package webhook

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	kubesecv2 "github.com/controlplaneio/kubectl-kubesec/v2/pkg/kubesec"
	"github.com/slok/kubewebhook/v2/pkg/log"
	kwhmodel "github.com/slok/kubewebhook/v2/pkg/model"
	"github.com/slok/kubewebhook/v2/pkg/webhook"
	"github.com/slok/kubewebhook/v2/pkg/webhook/validating"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kjson "k8s.io/apimachinery/pkg/runtime/serializer/json"
	"k8s.io/client-go/kubernetes/scheme"
)

// daemonSetsValidator validates the definition against the Kubesec.io score.
type daemonSetsValidator struct {
	minScore int
	logger   log.Logger
}

var _ validating.Validator = &daemonSetsValidator{}

func (d *daemonSetsValidator) Validate(_ context.Context, _ *kwhmodel.AdmissionReview, obj metav1.Object) (*validating.ValidatorResult, error) {
	kObj, ok := obj.(*appsv1.DaemonSet)
	if !ok {
		d.logger.Errorf("received invalid DaemonSet object %v", obj)
		return &validating.ValidatorResult{Valid: true}, nil
	}

	serializer := kjson.NewYAMLSerializer(kjson.DefaultMetaFactory, scheme.Scheme, scheme.Scheme)
	var buffer bytes.Buffer
	writer := bufio.NewWriter(&buffer)

	kObj.TypeMeta = metav1.TypeMeta{
		Kind:       "DaemonSet",
		APIVersion: "apps/v1",
	}

	err := serializer.Encode(kObj, writer)
	if err != nil {
		d.logger.Errorf("daemonset serialization failed %v", err)
		return &validating.ValidatorResult{Valid: true}, nil
	}

	if err := writer.Flush(); err != nil {
		d.logger.Errorf("failed to flush buffer %v", err)
		return &validating.ValidatorResult{Valid: true}, nil
	}

	d.logger.Infof("Scanning daemonset %s", kObj.Name)

	result, err := kubesecv2.NewClient(kubesecScanURL, timeOut).
		ScanDefinition(buffer)

	if err != nil {
		d.logger.Errorf("kubesec.io scan failed %v", err)
		return &validating.ValidatorResult{Valid: true}, nil
	}

	if len(result) != 1 {
		d.logger.Errorf("daemonset %q scan failed as result is empty", kObj.Name)
		return &validating.ValidatorResult{Valid: true}, nil
	}

	if result[0].Error != "" {
		d.logger.Errorf("kubesec.io scan failed %v", result[0].Error)
		return &validating.ValidatorResult{Valid: true}, nil
	}

	jq, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		d.logger.Errorf("kubesec.io pretty printing issue %v", err)
		return &validating.ValidatorResult{Valid: true}, nil
	}
	d.logger.Infof("Scan Result:\n%s", jq)

	if result[0].Score < d.minScore {
		return &validating.ValidatorResult{
			Valid:   false,
			Message: fmt.Sprintf("%s score is %d, daemonset minimum accepted score is %d\nScan Result:\n%s", kObj.Name, result[0].Score, d.minScore, jq),
		}, nil
	}

	return &validating.ValidatorResult{Valid: true}, nil
}

// NewDaemonSetWebhook returns a new DaemonSet validating webhook.
func NewDaemonSetWebhook(minScore int, logger log.Logger) (webhook.Webhook, error) {
	// Create validators.
	val := &daemonSetsValidator{
		minScore: minScore,
		logger:   logger,
	}

	cfg := validating.WebhookConfig{
		ID:        "kubesec-daemonset",
		Obj:       &appsv1.DaemonSet{},
		Validator: val,
		Logger:    logger,
	}

	return validating.NewWebhook(cfg)
}
