// Copyright (c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package consumer

import (
	"net/http"
	"net/http/httptest"
	"testing"

	pcfContext "github.com/omec-project/pcf/context"
)

func TestSendDeregisterNFInstance_AcceptsNoContentOnly(t *testing.T) {
	originalNrfURI := pcfContext.PCF_Self().NrfUri
	originalNfID := pcfContext.PCF_Self().NfId
	defer func() {
		pcfContext.PCF_Self().NrfUri = originalNrfURI
		pcfContext.PCF_Self().NfId = originalNfID
	}()

	tests := []struct {
		name       string
		statusCode int
		wantErr    bool
	}{
		{name: "No Content is success", statusCode: http.StatusNoContent, wantErr: false},
		{name: "Bad Request is error", statusCode: http.StatusBadRequest, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodDelete {
					t.Fatalf("unexpected method: %s", r.Method)
				}
				w.WriteHeader(tt.statusCode)
			}))
			defer server.Close()

			pcfContext.PCF_Self().NrfUri = server.URL
			pcfContext.PCF_Self().NfId = "test-nf-id"

			err := SendDeregisterNFInstance()
			if (err != nil) != tt.wantErr {
				t.Fatalf("SendDeregisterNFInstance() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
