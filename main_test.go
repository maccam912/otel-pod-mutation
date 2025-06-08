package main

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestCreatePatchesForPod(t *testing.T) {
	tests := []struct {
		name     string
		pod      *corev1.Pod
		expected int
	}{
		{
			name: "Pod without annotations",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pod",
					Namespace: "default",
				},
			},
			expected: 2,
		},
		{
			name: "Pod with empty annotations",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "test-pod",
					Namespace:   "default",
					Annotations: map[string]string{},
				},
			},
			expected: 1,
		},
		{
			name: "Pod with existing otel annotation",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pod",
					Namespace: "default",
					Annotations: map[string]string{
						otelAnnotationKey: otelAnnotationValue,
					},
				},
			},
			expected: 0,
		},
		{
			name: "Pod with other annotations but no otel",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pod",
					Namespace: "default",
					Annotations: map[string]string{
						"some.other/annotation": "value",
					},
				},
			},
			expected: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			patches := createPatchesForPod(tt.pod)
			if len(patches) != tt.expected {
				t.Errorf("Expected %d patches, got %d", tt.expected, len(patches))
			}

			if tt.expected > 0 {
				found := false
				for _, patch := range patches {
					if patch.Path == "/metadata/annotations/"+escapeJSONPointer(otelAnnotationKey) && patch.Value == otelAnnotationValue {
						found = true
						break
					}
				}
				if tt.expected == 1 && !found {
					t.Error("Expected to find OpenTelemetry annotation patch")
				}
			}
		})
	}
}

func TestEscapeJSONPointer(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{
			input:    "simple",
			expected: "simple",
		},
		{
			input:    "with/slash",
			expected: "with~1slash",
		},
		{
			input:    "with~tilde",
			expected: "with~0tilde",
		},
		{
			input:    "with/slash~and~tilde",
			expected: "with~1slash~0and~0tilde",
		},
		{
			input:    otelAnnotationKey,
			expected: "instrumentation.opentelemetry.io~1inject-python",
		},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := escapeJSONPointer(tt.input)
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestGetEnv(t *testing.T) {
	tests := []struct {
		name         string
		key          string
		defaultValue string
		envValue     string
		expected     string
	}{
		{
			name:         "Environment variable not set",
			key:          "TEST_VAR_NOT_SET",
			defaultValue: "default",
			envValue:     "",
			expected:     "default",
		},
		{
			name:         "Environment variable set",
			key:          "TEST_VAR_SET",
			defaultValue: "default",
			envValue:     "custom",
			expected:     "custom",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.envValue != "" {
				t.Setenv(tt.key, tt.envValue)
			}

			result := getEnv(tt.key, tt.defaultValue)
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}