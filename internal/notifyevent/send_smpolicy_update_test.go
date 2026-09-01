// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package notifyevent

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/omec-project/openapi/v2/models"
)

// The SMF advertises the base resource and routes the callback one segment below it.
//
// TS 29.512 defines the callback as {notificationUri}/update, and the SMF registers
// POST /nsmf-callback/sm-policies/{smContextRef}/update while advertising the URI without the
// suffix, so the polled trigger -- which calls this sender directly -- has to add it.
//
// The already-suffixed case is the one that matters most. The application-function callers reach
// this sender through DispatchSendSMPolicyUpdateNotifyEvent, which has appended the suffix since
// long before this change, so appending here unconditionally produced /update/update -- a 404
// indistinguishable from the one the suffix exists to prevent.
func TestNotificationGoesToTheUpdateCallback(t *testing.T) {
	const (
		base     = "/nsmf-callback/sm-policies/ref-1"
		callback = base + "/update"
	)

	tests := []struct {
		name string
		give string
		want string
	}{
		{"base uri", base, callback},
		{"trailing slash", base + "/", callback},
		{"already suffixed by the dispatcher", callback, callback},
		{"suffixed with a trailing slash", callback + "/", callback},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var gotPath string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotPath = r.URL.Path
				w.WriteHeader(http.StatusNoContent)
			}))
			defer srv.Close()

			err := SendSMPolicyUpdateNotification(srv.URL+tc.give, &models.SmPolicyNotification{})
			if err != nil {
				t.Fatalf("send failed: %v", err)
			}
			if gotPath != tc.want {
				t.Errorf("posted to %q, want %q — the SMF answers 404 on the base resource", gotPath, tc.want)
			}
		})
	}
}

// A 404 has to surface as an error. It is what the SMF returns for a callback it does not route,
// and treating it as delivered is how the defect above stayed invisible.
func TestUnroutedCallbackIsReportedAsAFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	err := SendSMPolicyUpdateNotification(srv.URL+"/nsmf-callback/sm-policies/ref-1",
		&models.SmPolicyNotification{})
	if err == nil {
		t.Fatal("a 404 was reported as a successful delivery")
	}
}
