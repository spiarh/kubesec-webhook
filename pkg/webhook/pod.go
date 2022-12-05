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
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kjson "k8s.io/apimachinery/pkg/runtime/serializer/json"
	"k8s.io/client-go/kubernetes/scheme"
)

// podValidator validates the definition against the Kubesec.io score.
type podValidator struct {
	minScore int
	logger   log.Logger
}

var _ validating.Validator = &podValidator{}

func (d *podValidator) Validate(_ context.Context, _ *kwhmodel.AdmissionReview, obj metav1.Object) (*validating.ValidatorResult, error) {
	kObj, ok := obj.(*v1.Pod)
	if !ok {
		return &validating.ValidatorResult{Valid: true}, nil
	}

	serializer := kjson.NewYAMLSerializer(kjson.DefaultMetaFactory, scheme.Scheme, scheme.Scheme)
	var buffer bytes.Buffer
	writer := bufio.NewWriter(&buffer)

	kObj.TypeMeta = metav1.TypeMeta{
		Kind:       "Pod",
		APIVersion: "v1",
	}

	err := serializer.Encode(kObj, writer)
	if err != nil {
		d.logger.Errorf("pod serialization failed %v", err)
		return &validating.ValidatorResult{Valid: true}, nil
	}

	if err := writer.Flush(); err != nil {
		d.logger.Errorf("failed to flush buffer %v", err)
		return &validating.ValidatorResult{Valid: true}, nil
	}

	d.logger.Infof("Scanning pod %s", kObj.Name)

	result, err := kubesecv2.NewClient(kubesecScanURL, timeOut).
		ScanDefinition(buffer)

	if err != nil {
		d.logger.Errorf("kubesec.io scan failed %v", err)
		return &validating.ValidatorResult{Valid: true}, nil
	}

	if len(result) != 1 {
		d.logger.Errorf("pod %q scan failed as result is empty", kObj.Name)
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
			Message: fmt.Sprintf("%s score is %d, minimum accepted score is %d\nScan Result:\n%s", kObj.Name, result[0].Score, d.minScore, jq),
		}, nil
	}

	return &validating.ValidatorResult{Valid: true}, nil
}

// NewPodWebhook returns a new deployment validating webhook.
func NewPodWebhook(minScore int, logger log.Logger) (webhook.Webhook, error) {
	// Create validators.
	val := &podValidator{
		minScore: minScore,
		logger:   logger,
	}

	cfg := validating.WebhookConfig{
		ID:        "kubesec-pod",
		Obj:       &v1.Pod{},
		Validator: val,
		Logger:    logger,
	}

	return validating.NewWebhook(cfg)
}
