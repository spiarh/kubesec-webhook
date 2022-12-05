package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
	kwhhttp "github.com/slok/kubewebhook/v2/pkg/http"
	"github.com/slok/kubewebhook/v2/pkg/log"
	kwhlogrus "github.com/slok/kubewebhook/v2/pkg/log/logrus"
	kwhwebhook "github.com/slok/kubewebhook/v2/pkg/webhook"

	// "github.com/slok/kubewebhook/v2/pkg/metrics/prometheus"
	kwhprometheus "github.com/slok/kubewebhook/v2/pkg/metrics/prometheus"

	"github.com/controlplaneio/kubesec-webhook/pkg/webhook"
)

// Defaults.
const (
	lAddressDef     = ":8080"
	lMetricsAddress = ":8081"
	debugDef        = false
	gracePeriod     = 3 * time.Second
)

// Flags are the flags of the program.
type Flags struct {
	ListenAddress        string
	MetricsListenAddress string
	Debug                bool
	CertFile             string
	KeyFile              string
	MinScore             int
}

// NewFlags returns the flags of the commandline.
func NewFlags() *Flags {
	flags := &Flags{}
	fl := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	fl.StringVar(&flags.ListenAddress, "listen-address", lAddressDef, "webhook server listen address")
	fl.StringVar(&flags.MetricsListenAddress, "metrics-listen-address", lMetricsAddress, "metrics server listen address")
	fl.BoolVar(&flags.Debug, "debug", debugDef, "enable debug mode")
	fl.StringVar(&flags.CertFile, "tls-cert-file", "certs/cert.pem", "TLS certificate file")
	fl.StringVar(&flags.KeyFile, "tls-key-file", "certs/key.pem", "TLS key file")
	fl.IntVar(&flags.MinScore, "min-score", 0, "Kubesec.io minimum score to validate against")

	if err := fl.Parse(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "%s", err)
		os.Exit(1)
	}

	return flags
}

type Main struct {
	flags  *Flags
	logger log.Logger
	stopC  chan struct{}
}

// Run will run the main program.
func (m *Main) Run() error {
	// Logging
	logrusLogEntry := logrus.NewEntry(logrus.New())
	if m.flags.Debug {
		logrusLogEntry.Logger.SetLevel(logrus.DebugLevel)
	}
	m.logger = kwhlogrus.NewLogrus(logrusLogEntry)

	// Register metrics
	promReg := prometheus.NewRegistry()
	metricsRec, err := kwhprometheus.NewRecorder(kwhprometheus.RecorderConfig{Registry: promReg})
	if err != nil {
		return fmt.Errorf("could not create Prometheus metrics recorder: %w", err)
	}

	// Pods
	podWebhook, err := webhook.NewPodWebhook(m.flags.MinScore, m.logger)
	if err != nil {
		return err
	}

	podHandler, err := kwhhttp.HandlerFor(kwhhttp.HandlerConfig{
		Webhook: kwhwebhook.NewMeasuredWebhook(metricsRec, podWebhook),
		Logger:  m.logger})
	if err != nil {
		return fmt.Errorf("error creating pod webhook handler: %w", err)
	}

	// Deployments
	deploymentWebhook, err := webhook.NewDeploymentWebhook(m.flags.MinScore, m.logger)
	if err != nil {
		return err
	}
	deploymentHandler, err := kwhhttp.HandlerFor(kwhhttp.HandlerConfig{
		Webhook: kwhwebhook.NewMeasuredWebhook(metricsRec, deploymentWebhook),
		Logger:  m.logger})
	if err != nil {
		return fmt.Errorf("error creating deployment webhook handler: %w", err)
	}

	// DaemonSets
	daemonSetWebhook, err := webhook.NewDaemonSetWebhook(m.flags.MinScore, m.logger)
	if err != nil {
		return err
	}
	daemonSetHandler, err := kwhhttp.HandlerFor(kwhhttp.HandlerConfig{
		Webhook: kwhwebhook.NewMeasuredWebhook(metricsRec, daemonSetWebhook),
		Logger:  m.logger})
	if err != nil {
		return fmt.Errorf("error creating daemonset webhook handler: %w", err)
	}

	// StatefulSets
	statefulSetWebhook, err := webhook.NewStatefulSetWebhook(m.flags.MinScore, m.logger)
	if err != nil {
		return err
	}
	statefulSetHandler, err := kwhhttp.HandlerFor(kwhhttp.HandlerConfig{
		Webhook: kwhwebhook.NewMeasuredWebhook(metricsRec, statefulSetWebhook),
		Logger:  m.logger})
	if err != nil {
		return fmt.Errorf("error creating statefulset webhook handler: %w", err)
	}

	errC := make(chan error)

	// Serve webhooks
	go func() {
		m.logger.Infof("webhooks listening on %s...", m.flags.ListenAddress)
		mux := http.NewServeMux()
		mux.Handle("/pod", podHandler)
		mux.Handle("/deployment", deploymentHandler)
		mux.Handle("/daemonset", daemonSetHandler)
		mux.Handle("/statefulset", statefulSetHandler)
		errC <- http.ListenAndServeTLS(
			m.flags.ListenAddress,
			m.flags.CertFile,
			m.flags.KeyFile,
			mux,
		)
	}()

	// Serve metrics.
	metricsHandler := promhttp.HandlerFor(promReg, promhttp.HandlerOpts{})
	go func() {
		m.logger.Infof("metrics listening on %s...", m.flags.MetricsListenAddress)
		errC <- http.ListenAndServe(m.flags.MetricsListenAddress, metricsHandler)
	}()

	// Run everything
	defer m.stop()

	sigC := m.createSignalChan()
	select {
	case err := <-errC:
		if err != nil {
			m.logger.Errorf("error received: %s", err)
			return err
		}
		m.logger.Infof("app finished successfuly")
	case s := <-sigC:
		m.logger.Infof("signal %s received", s)
		return nil
	}

	return nil
}

func (m *Main) stop() {
	m.logger.Infof("stopping everything, waiting %s...", gracePeriod)

	close(m.stopC)

	// Stop everything and let them time to stop.
	time.Sleep(gracePeriod)
}

func (m *Main) createSignalChan() chan os.Signal {
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGTERM, syscall.SIGINT)
	return c
}

func main() {
	m := Main{
		flags: NewFlags(),
		stopC: make(chan struct{}),
	}

	err := m.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s", err)
		os.Exit(1)
	}
	os.Exit(0)
}
