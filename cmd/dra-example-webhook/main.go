/*
Copyright 2025 The Kubernetes Authors.

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

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/urfave/cli/v2"

	v1 "k8s.io/api/admission/v1"
	"k8s.io/api/admission/v1beta1"
	resourceapi "k8s.io/api/resource/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/klog/v2"

	configapi "sigs.k8s.io/dra-example-driver/api/example.com/resource/gpu/v1alpha1"
	"sigs.k8s.io/dra-example-driver/pkg/flags"
)

const DriverName = "gpu.example.com"

type Flags struct {
	kubeClientConfig flags.KubeClientConfig
	loggingConfig    *flags.LoggingConfig

	certFile string
	keyFile  string
	port     int
}

func main() {
	if err := newApp().Run(os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func newApp() *cli.App {
	flags := &Flags{
		loggingConfig: flags.NewLoggingConfig(),
	}
	cliFlags := []cli.Flag{
		&cli.StringFlag{
			Name:        "tls-cert-file",
			Usage:       "File containing the default x509 Certificate for HTTPS. (CA cert, if any, concatenated after server cert).",
			Destination: &flags.certFile,
		},
		&cli.StringFlag{
			Name:        "tls-private-key-file",
			Usage:       "File containing the default x509 private key matching --tls-cert-file.",
			Destination: &flags.keyFile,
		},
		&cli.IntFlag{
			Name:        "port",
			Usage:       "Secure port that the webhook listens on",
			Value:       443,
			Destination: &flags.port,
		},
	}
	cliFlags = append(cliFlags, flags.kubeClientConfig.Flags()...)
	cliFlags = append(cliFlags, flags.loggingConfig.Flags()...)

	app := &cli.App{
		Name:            "dra-example-webhook",
		Usage:           "dra-example-webhook implements a validating admission webhook complementing a DRA driver plugin.",
		ArgsUsage:       " ",
		HideHelpCommand: true,
		Flags:           cliFlags,
		Before: func(c *cli.Context) error {
			if c.Args().Len() > 0 {
				return fmt.Errorf("arguments not supported: %v", c.Args().Slice())
			}
			return flags.loggingConfig.Apply()
		},
		Action: func(c *cli.Context) error {
			http.HandleFunc("/validate-resource-claims", serveResourceClaim)
			http.HandleFunc("/readyz", func(w http.ResponseWriter, req *http.Request) { w.Write([]byte("ok")) })
			server := &http.Server{
				Addr: fmt.Sprintf(":%d", flags.port),
			}
			return server.ListenAndServeTLS(flags.certFile, flags.keyFile)
		},
	}

	return app
}

// admitv1beta1Func handles a v1beta1 admission
type admitv1beta1Func func(v1beta1.AdmissionReview) *v1beta1.AdmissionResponse

// admitv1beta1Func handles a v1 admission
type admitv1Func func(v1.AdmissionReview) *v1.AdmissionResponse

// admitHandler is a handler, for both validators and mutators, that supports multiple admission review versions
type admitHandler struct {
	v1beta1 admitv1beta1Func
	v1      admitv1Func
}

func newDelegateToV1AdmitHandler(f admitv1Func) admitHandler {
	return admitHandler{
		v1beta1: delegateV1beta1AdmitToV1(f),
		v1:      f,
	}
}

func delegateV1beta1AdmitToV1(f admitv1Func) admitv1beta1Func {
	return func(review v1beta1.AdmissionReview) *v1beta1.AdmissionResponse {
		in := v1.AdmissionReview{Request: convertAdmissionRequestToV1(review.Request)}
		out := f(in)
		return convertAdmissionResponseToV1beta1(out)
	}
}

// serve handles the http portion of a request prior to handing to an admit
// function
func serve(w http.ResponseWriter, r *http.Request, admit admitHandler) {
	var body []byte
	if r.Body != nil {
		if data, err := io.ReadAll(r.Body); err == nil {
			body = data
		}
	}

	// verify the content type is accurate
	contentType := r.Header.Get("Content-Type")
	if contentType != "application/json" {
		klog.Errorf("contentType=%s, expect application/json", contentType)
		return
	}

	klog.V(2).Info(fmt.Sprintf("handling request: %s", body))

	deserializer := codecs.UniversalDeserializer()
	obj, gvk, err := deserializer.Decode(body, nil, nil)
	if err != nil {
		msg := fmt.Sprintf("Request could not be decoded: %v", err)
		klog.Error(msg)
		http.Error(w, msg, http.StatusBadRequest)
		return
	}

	var responseObj runtime.Object
	switch *gvk {
	case v1beta1.SchemeGroupVersion.WithKind("AdmissionReview"):
		requestedAdmissionReview, ok := obj.(*v1beta1.AdmissionReview)
		if !ok {
			klog.Errorf("Expected v1beta1.AdmissionReview but got: %T", obj)
			return
		}
		responseAdmissionReview := &v1beta1.AdmissionReview{}
		responseAdmissionReview.SetGroupVersionKind(*gvk)
		responseAdmissionReview.Response = admit.v1beta1(*requestedAdmissionReview)
		responseAdmissionReview.Response.UID = requestedAdmissionReview.Request.UID
		responseObj = responseAdmissionReview
	case v1.SchemeGroupVersion.WithKind("AdmissionReview"):
		requestedAdmissionReview, ok := obj.(*v1.AdmissionReview)
		if !ok {
			klog.Errorf("Expected v1.AdmissionReview but got: %T", obj)
			return
		}
		responseAdmissionReview := &v1.AdmissionReview{}
		responseAdmissionReview.SetGroupVersionKind(*gvk)
		responseAdmissionReview.Response = admit.v1(*requestedAdmissionReview)
		responseAdmissionReview.Response.UID = requestedAdmissionReview.Request.UID
		responseObj = responseAdmissionReview
	default:
		msg := fmt.Sprintf("Unsupported group version kind: %v", gvk)
		klog.Error(msg)
		http.Error(w, msg, http.StatusBadRequest)
		return
	}

	klog.V(2).Info(fmt.Sprintf("sending response: %v", responseObj))
	respBytes, err := json.Marshal(responseObj)
	if err != nil {
		klog.Error(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(respBytes); err != nil {
		klog.Error(err)
	}
}

func serveResourceClaim(w http.ResponseWriter, r *http.Request) {
	serve(w, r, newDelegateToV1AdmitHandler(admitResourceClaim))
}

func admitResourceClaim(ar v1.AdmissionReview) *v1.AdmissionResponse {
	klog.V(2).Info("admitting resourceclaims")

	resourceClaimResource := metav1.GroupVersionResource{Group: "resource", Version: "v1beta1", Resource: "resourceclaims"}
	if ar.Request.Resource != resourceClaimResource {
		klog.Errorf("expect resource to be %s", resourceClaimResource)
		return nil
	}

	var raw []byte
	if ar.Request.Operation == v1.Delete {
		raw = ar.Request.OldObject.Raw
	} else {
		raw = ar.Request.Object.Raw
	}

	claim := resourceapi.ResourceClaim{}
	deserializer := codecs.UniversalDeserializer()
	if _, _, err := deserializer.Decode(raw, nil, &claim); err != nil {
		klog.Error(err)
		return toV1AdmissionResponse(err)
	}

	reviewResponse := v1.AdmissionResponse{}
	reviewResponse.Allowed = true

	var errs field.ErrorList
	for configIndex, config := range claim.Spec.Devices.Config {
		if config.Opaque == nil || config.Opaque.Driver != DriverName {
			continue
		}

		fieldPath := field.NewPath("spec", "devices", "config").
			Index(configIndex).
			Child("opaque", "parameters")

		decodedConfig, err := runtime.Decode(configapi.Decoder, config.DeviceConfiguration.Opaque.Parameters.Raw)
		if err != nil {
			// TODO: common user mistakes like an incorrect API version might cause this to fail in a way that
			// wouldn't necessarily be an internal error.
			errs = append(errs, field.InternalError(fieldPath, fmt.Errorf("error decoding: %w", err)))
			continue
		}
		err = decodedConfig.(*configapi.GpuConfig).Validate()
		if err != nil {
			errs = append(errs, field.Invalid(fieldPath, decodedConfig, err.Error()))
		}
	}

	if err := errs.ToAggregate(); err != nil {
		reviewResponse.Allowed = false
		reviewResponse.Result = &metav1.Status{
			Reason: metav1.StatusReason(err.Error()),
		}
	}

	return &reviewResponse
}
