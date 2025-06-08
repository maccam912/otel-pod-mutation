package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/klog/v2"
)

var (
	scheme = runtime.NewScheme()
	codecs = serializer.NewCodecFactory(scheme)
)

const (
	otelAnnotationKey   = "instrumentation.opentelemetry.io/inject-python"
	otelAnnotationValue = "opentelemetry-operator-system/instrumentation"
)

type WebhookServer struct {
	server *http.Server
}

type patchOperation struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value"`
}

func main() {
	klog.InitFlags(nil)

	certPath := getEnv("TLS_CERT_FILE", "/etc/certs/tls.crt")
	keyPath := getEnv("TLS_KEY_FILE", "/etc/certs/tls.key")
	port := getEnv("WEBHOOK_PORT", "8443")

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		klog.Fatalf("Failed to load key pair: %v", err)
	}

	webhookServer := &WebhookServer{
		server: &http.Server{
			Addr:      fmt.Sprintf(":%s", port),
			TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}},
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/mutate", webhookServer.mutate)
	mux.HandleFunc("/health", webhookServer.health)
	webhookServer.server.Handler = mux

	klog.Info("Starting webhook server...")
	go func() {
		if err := webhookServer.server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			klog.Fatalf("Failed to start webhook server: %v", err)
		}
	}()

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
	<-signalChan

	klog.Info("Shutting down webhook server...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := webhookServer.server.Shutdown(ctx); err != nil {
		klog.Fatalf("Failed to shutdown webhook server: %v", err)
	}
}

func (ws *WebhookServer) mutate(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		klog.Errorf("Failed to read request body: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var review admissionv1.AdmissionReview
	if err := json.Unmarshal(body, &review); err != nil {
		klog.Errorf("Failed to unmarshal admission review: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	req := review.Request
	var pod corev1.Pod
	if err := json.Unmarshal(req.Object.Raw, &pod); err != nil {
		klog.Errorf("Failed to unmarshal pod: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	patches := createPatchesForPod(&pod)

	patchBytes, err := json.Marshal(patches)
	if err != nil {
		klog.Errorf("Failed to marshal patches: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	response := &admissionv1.AdmissionResponse{
		UID:     req.UID,
		Allowed: true,
	}

	if len(patches) > 0 {
		response.PatchType = func() *admissionv1.PatchType {
			pt := admissionv1.PatchTypeJSONPatch
			return &pt
		}()
		response.Patch = patchBytes
		klog.Infof("Applied OpenTelemetry instrumentation patch to pod %s/%s", pod.Namespace, pod.Name)
	}

	review.Response = response
	respBytes, err := json.Marshal(review)
	if err != nil {
		klog.Errorf("Failed to marshal admission response: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(respBytes)
}

func (ws *WebhookServer) health(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func createPatchesForPod(pod *corev1.Pod) []patchOperation {
	var patches []patchOperation

	if pod.Annotations == nil {
		patches = append(patches, patchOperation{
			Op:    "add",
			Path:  "/metadata/annotations",
			Value: map[string]string{},
		})
	}

	if _, exists := pod.Annotations[otelAnnotationKey]; !exists {
		if pod.Annotations == nil {
			patches = append(patches, patchOperation{
				Op:    "add",
				Path:  "/metadata/annotations/" + escapeJSONPointer(otelAnnotationKey),
				Value: otelAnnotationValue,
			})
		} else {
			patches = append(patches, patchOperation{
				Op:    "add",
				Path:  "/metadata/annotations/" + escapeJSONPointer(otelAnnotationKey),
				Value: otelAnnotationValue,
			})
		}
	}

	return patches
}

func escapeJSONPointer(s string) string {
	s = strings.ReplaceAll(s, "~", "~0")
	s = strings.ReplaceAll(s, "/", "~1")
	return s
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
