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
	klog.Info("=== WEBHOOK STARTUP BEGIN ===")
	klog.V(2).Info("Debug logging enabled - trace level")

	// Log all environment variables for debugging
	klog.V(2).Info("Environment variables:")
	for _, env := range os.Environ() {
		klog.V(3).Infof("  %s", env)
	}

	certPath := getEnv("TLS_CERT_FILE", "/etc/certs/tls.crt")
	keyPath := getEnv("TLS_KEY_FILE", "/etc/certs/tls.key")
	port := getEnv("WEBHOOK_PORT", "8443")

	klog.V(2).Infof("Configuration loaded: certPath=%s, keyPath=%s, port=%s", certPath, keyPath, port)

	// Check if certificate files exist and are readable
	klog.V(2).Info("Checking certificate files...")

	// List the certificate directory
	certDir := "/etc/certs"
	klog.V(2).Infof("Listing certificate directory: %s", certDir)
	if entries, err := os.ReadDir(certDir); err != nil {
		klog.Errorf("Failed to read certificate directory %s: %v", certDir, err)
	} else {
		klog.V(2).Infof("Certificate directory contains %d entries:", len(entries))
		for _, entry := range entries {
			info, _ := entry.Info()
			klog.V(2).Infof("  %s (mode: %v, size: %d)", entry.Name(), info.Mode(), info.Size())
		}
	}

	if stat, err := os.Stat(certPath); os.IsNotExist(err) {
		klog.Errorf("Certificate file does not exist: %s", certPath)
	} else if err != nil {
		klog.Errorf("Error accessing certificate file %s: %v", certPath, err)
	} else {
		klog.V(2).Infof("Certificate file exists: %s (mode: %v, size: %d)", certPath, stat.Mode(), stat.Size())
	}

	if stat, err := os.Stat(keyPath); os.IsNotExist(err) {
		klog.Errorf("Key file does not exist: %s", keyPath)
	} else if err != nil {
		klog.Errorf("Error accessing key file %s: %v", keyPath, err)
	} else {
		klog.V(2).Infof("Key file exists: %s (mode: %v, size: %d)", keyPath, stat.Mode(), stat.Size())
	}

	klog.V(2).Info("Loading TLS certificate pair...")
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		klog.Errorf("Failed to load key pair from certPath=%s, keyPath=%s: %v", certPath, keyPath, err)
		klog.Fatalf("Failed to load key pair: %v", err)
	}
	klog.V(2).Info("TLS certificate pair loaded successfully")

	klog.V(2).Info("Creating webhook server instance...")
	webhookServer := &WebhookServer{
		server: &http.Server{
			Addr:      fmt.Sprintf(":%s", port),
			TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}},
		},
	}
	klog.V(2).Infof("Webhook server created with address: %s", webhookServer.server.Addr)

	klog.V(2).Info("Setting up HTTP routes...")
	mux := http.NewServeMux()
	mux.HandleFunc("/mutate", webhookServer.mutate)
	mux.HandleFunc("/health", webhookServer.health)
	webhookServer.server.Handler = mux
	klog.V(2).Info("HTTP routes configured: /mutate, /health")

	klog.Info("Starting webhook server...")
	klog.V(2).Infof("About to start ListenAndServeTLS on port %s", port)

	// Add channel for server startup errors
	startupErrChan := make(chan error, 1)
	go func() {
		klog.V(2).Info("Starting TLS server goroutine...")
		if err := webhookServer.server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			klog.Errorf("Server failed to start or crashed: %v", err)
			startupErrChan <- err
			klog.Fatalf("Failed to start webhook server: %v", err)
		}
		klog.V(2).Info("TLS server goroutine exited normally")
	}()

	// Give the server a moment to start up and check for immediate failures
	klog.V(2).Info("Waiting for server startup...")
	select {
	case err := <-startupErrChan:
		klog.Fatalf("Server failed during startup: %v", err)
	case <-time.After(2 * time.Second):
		klog.Info("Server appears to have started successfully")
	}

	klog.V(2).Info("Setting up signal handling...")
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
	klog.Info("Webhook server is ready and waiting for signals...")

	sig := <-signalChan
	klog.Infof("Received signal: %v", sig)

	klog.Info("Shutting down webhook server...")
	klog.V(2).Info("Creating shutdown context with 10 second timeout...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	klog.V(2).Info("Calling server.Shutdown()...")
	if err := webhookServer.server.Shutdown(ctx); err != nil {
		klog.Errorf("Error during server shutdown: %v", err)
		klog.Fatalf("Failed to shutdown webhook server: %v", err)
	}
	klog.Info("Webhook server shutdown completed successfully")
	klog.Info("=== WEBHOOK SHUTDOWN COMPLETE ===")
}

func (ws *WebhookServer) mutate(w http.ResponseWriter, r *http.Request) {
	klog.V(2).Infof("=== MUTATE REQUEST START === Method: %s, URL: %s, RemoteAddr: %s", r.Method, r.URL.Path, r.RemoteAddr)
	klog.V(3).Infof("Request headers: %+v", r.Header)

	body, err := io.ReadAll(r.Body)
	if err != nil {
		klog.Errorf("Failed to read request body: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	klog.V(3).Infof("Request body length: %d bytes", len(body))
	klog.V(4).Infof("Raw request body: %s", string(body))

	var review admissionv1.AdmissionReview
	if err := json.Unmarshal(body, &review); err != nil {
		klog.Errorf("Failed to unmarshal admission review: %v", err)
		klog.V(3).Infof("Failed body content: %s", string(body))
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	klog.V(2).Infof("Successfully unmarshaled admission review, UID: %s", review.Request.UID)

	req := review.Request
	klog.V(2).Infof("Processing admission request for kind: %s, namespace: %s, name: %s", req.Kind.Kind, req.Namespace, req.Name)

	var pod corev1.Pod
	if err := json.Unmarshal(req.Object.Raw, &pod); err != nil {
		klog.Errorf("Failed to unmarshal pod: %v", err)
		klog.V(3).Infof("Failed pod object: %s", string(req.Object.Raw))
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	klog.V(2).Infof("Successfully unmarshaled pod: %s/%s", pod.Namespace, pod.Name)
	klog.V(3).Infof("Pod annotations: %+v", pod.Annotations)

	klog.V(2).Info("Creating patches for pod...")
	patches := createPatchesForPod(&pod)
	klog.V(2).Infof("Created %d patches", len(patches))

	klog.V(3).Infof("Marshaling %d patches: %+v", len(patches), patches)
	patchBytes, err := json.Marshal(patches)
	if err != nil {
		klog.Errorf("Failed to marshal patches: %v", err)
		klog.V(3).Infof("Failed patches: %+v", patches)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	klog.V(3).Infof("Marshaled patch bytes length: %d", len(patchBytes))
	klog.V(4).Infof("Patch JSON: %s", string(patchBytes))

	klog.V(2).Info("Creating admission response...")
	response := &admissionv1.AdmissionResponse{
		UID:     req.UID,
		Allowed: true,
	}
	klog.V(3).Infof("Base response created with UID: %s, Allowed: %t", response.UID, response.Allowed)

	if len(patches) > 0 {
		klog.V(2).Info("Adding patches to response...")
		response.PatchType = func() *admissionv1.PatchType {
			pt := admissionv1.PatchTypeJSONPatch
			return &pt
		}()
		response.Patch = patchBytes
		klog.Infof("Applied OpenTelemetry instrumentation patch to pod %s/%s", pod.Namespace, pod.Name)
		klog.V(3).Infof("Response now includes %d patches", len(patches))
	} else {
		klog.V(2).Info("No patches needed for this pod")
	}

	review.Response = response
	klog.V(2).Info("Marshaling final admission review response...")
	respBytes, err := json.Marshal(review)
	if err != nil {
		klog.Errorf("Failed to marshal admission response: %v", err)
		klog.V(3).Infof("Failed response: %+v", review)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	klog.V(3).Infof("Final response bytes length: %d", len(respBytes))
	klog.V(4).Infof("Final response JSON: %s", string(respBytes))

	klog.V(2).Info("Sending response...")
	w.Header().Set("Content-Type", "application/json")
	w.Write(respBytes)
	klog.V(2).Info("=== MUTATE REQUEST COMPLETE ===")
}

func (ws *WebhookServer) health(w http.ResponseWriter, r *http.Request) {
	klog.V(3).Infof("Health check request from %s", r.RemoteAddr)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
	klog.V(3).Info("Health check response sent")
}

func createPatchesForPod(pod *corev1.Pod) []patchOperation {
	klog.V(2).Infof("Creating patches for pod %s/%s", pod.Namespace, pod.Name)
	var patches []patchOperation

	klog.V(3).Infof("Checking if pod has annotations... Current annotations: %+v", pod.Annotations)
	if pod.Annotations == nil {
		klog.V(2).Info("Pod has no annotations, adding empty annotations map")
		patches = append(patches, patchOperation{
			Op:    "add",
			Path:  "/metadata/annotations",
			Value: map[string]string{},
		})
		klog.V(3).Infof("Added empty annotations patch: %+v", patches[len(patches)-1])
	}

	klog.V(3).Infof("Checking for OpenTelemetry annotation key: %s", otelAnnotationKey)
	if _, exists := pod.Annotations[otelAnnotationKey]; !exists {
		klog.V(2).Infof("OpenTelemetry annotation not found, adding it with value: %s", otelAnnotationValue)
		escapedKey := escapeJSONPointer(otelAnnotationKey)
		klog.V(3).Infof("Escaped annotation key: %s -> %s", otelAnnotationKey, escapedKey)

		if pod.Annotations == nil {
			klog.V(3).Info("Adding annotation to nil annotations map")
			patches = append(patches, patchOperation{
				Op:    "add",
				Path:  "/metadata/annotations/" + escapedKey,
				Value: otelAnnotationValue,
			})
		} else {
			klog.V(3).Info("Adding annotation to existing annotations map")
			patches = append(patches, patchOperation{
				Op:    "add",
				Path:  "/metadata/annotations/" + escapedKey,
				Value: otelAnnotationValue,
			})
		}
		klog.V(3).Infof("Added annotation patch: %+v", patches[len(patches)-1])
	} else {
		klog.V(2).Infof("OpenTelemetry annotation already exists with value: %s", pod.Annotations[otelAnnotationKey])
	}

	klog.V(2).Infof("Final patches count: %d", len(patches))
	klog.V(3).Infof("All patches: %+v", patches)
	return patches
}

func escapeJSONPointer(s string) string {
	klog.V(4).Infof("Escaping JSON pointer: %s", s)
	original := s
	s = strings.ReplaceAll(s, "~", "~0")
	s = strings.ReplaceAll(s, "/", "~1")
	klog.V(4).Infof("Escaped JSON pointer: %s -> %s", original, s)
	return s
}

func getEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value != "" {
		klog.V(3).Infof("Environment variable %s = %s", key, value)
		return value
	}
	klog.V(3).Infof("Environment variable %s not set, using default: %s", key, defaultValue)
	return defaultValue
}
