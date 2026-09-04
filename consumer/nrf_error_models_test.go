// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package consumer

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/omec-project/openapi/v2/models"
	pcf_context "github.com/omec-project/pcf/context"
)

const (
	peerErrTitle  = "Subscription rejected"
	peerErrDetail = "the peer does not accept subscriptions from this NF type"
	peerErrCause  = "SUBSCRIPTION_NOT_ALLOWED"
)

func ptrString(s string) *string { return &s }

func ptrInt32(i int32) *int32 { return &i }

// peerReturning stands up a peer answering every request with the given status. A body is written
// only for a status the generated client has an arm for; for any other status the client leaves
// RawError equal to the status, which is the case the removed guard used to let through.
func peerReturning(t *testing.T, status int, withBody bool) *httptest.Server {
	t.Helper()

	body, err := json.Marshal(models.ProblemDetails{
		Title:  ptrString(peerErrTitle),
		Detail: ptrString(peerErrDetail),
		Cause:  ptrString(peerErrCause),
		Status: ptrInt32(int32(status)),
	})
	if err != nil {
		t.Fatalf("marshalling the problem details: %v", err)
	}

	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if withBody {
			w.Header().Set("Content-Type", "application/problem+json")
		}
		w.WriteHeader(status)
		if withBody {
			if _, writeErr := w.Write(body); writeErr != nil {
				t.Errorf("writing the response body: %v", writeErr)
			}
		}
	}))

	// SendUpdateNFInstance and SendRemoveSubscription read the NRF URI from the process-wide PCF
	// context rather than taking it as an argument, so it is set here - and restored, because
	// otherwise a later test in this package inherits a URL whose server has already been closed.
	// Same save-and-restore as TestSendDeregisterNFInstance_AcceptsNoContentOnly.
	originalNrfURI := pcf_context.PCF_Self().NrfUri
	pcf_context.PCF_Self().NrfUri = svr.URL
	t.Cleanup(func() {
		pcf_context.PCF_Self().NrfUri = originalNrfURI
		svr.Close()
	})

	return svr
}

func assertPeerProblem(t *testing.T, problem *models.ProblemDetails) {
	t.Helper()

	if problem == nil {
		t.Fatal("problemDetails = nil, want the ProblemDetails the peer sent; the response body " +
			"decoded and was then discarded, which is the defect this test pins")
	}
	if got := problem.GetTitle(); got != peerErrTitle {
		t.Errorf("Title = %q, want %q", got, peerErrTitle)
	}
	if got := problem.GetDetail(); got != peerErrDetail {
		t.Errorf("Detail = %q, want %q", got, peerErrDetail)
	}
	if got := problem.GetCause(); got != peerErrCause {
		t.Errorf("Cause = %q, want %q", got, peerErrCause)
	}
}

// assertErrAlongsideProblem pins the existing contract of the three nf_management functions: a
// refused request returns the ProblemDetails *and* the error, and every caller checks the problem
// first. The error is the client's, so it still carries the status.
func assertErrAlongsideProblem(t *testing.T, err error) {
	t.Helper()

	if err == nil {
		t.Error("err = nil, want the client's error: these functions return both, and callers " +
			"that only look at err would otherwise read a refusal as success")
	}
}

// The guard fired precisely when there was something to read: the generated client replaces its
// error string with FormatErrorMessage(status, model) as soon as a body decodes, so for a decoded
// ProblemDetails err.Error() never equals res.Status.
func TestSendUpdateNFInstanceReturnsTheProblemDetails(t *testing.T) {
	peerReturning(t, http.StatusForbidden, true)

	// A non-empty patch: the generated client validates the slice before sending, so an empty
	// one never reaches the peer and the test would assert against a client-side error instead.
	_, problem, err := SendUpdateNFInstance([]models.PatchItem{{
		Op:    models.PATCHOPERATION_REPLACE,
		Path:  "/nfStatus",
		Value: models.NFSTATUS_REGISTERED,
	}})

	assertPeerProblem(t, problem)
	assertErrAlongsideProblem(t, err)
}

func TestSendCreateSubscriptionReturnsTheProblemDetails(t *testing.T) {
	svr := peerReturning(t, http.StatusForbidden, true)

	_, problem, err := SendCreateSubscription(svr.URL, models.SubscriptionData{})

	assertPeerProblem(t, problem)
	assertErrAlongsideProblem(t, err)
}

func TestSendRemoveSubscriptionReturnsTheProblemDetails(t *testing.T) {
	peerReturning(t, http.StatusForbidden, true)

	problem, err := SendRemoveSubscription("subscription-id")

	assertPeerProblem(t, problem)
	assertErrAlongsideProblem(t, err)
}

func TestAmfStatusChangeSubscribeReturnsTheProblemDetails(t *testing.T) {
	svr := peerReturning(t, http.StatusForbidden, true)

	problem, err := AmfStatusChangeSubscribe(svr.URL, []models.Guami{})

	assertPeerProblem(t, problem)
	// Unlike the three above, this one reports the refusal through problemDetails alone. Both
	// shapes are pre-existing and both callers check problemDetails first, so the difference is
	// pinned here rather than changed.
	if err != nil {
		t.Errorf("err = %v, want nil: this function reports a refusal through problemDetails", err)
	}
}

// A status the generated client names by no arm leaves RawError equal to the status, so the
// removed guard passed it straight into the assertion below - which asked for the value type while
// the client returns *GenericOpenAPIError, and so panicked. 504 is the realistic instance: an
// intermediary can produce it without the AMF being involved at all.
//
// The assertion is that the call returns. Before the fix this test did not fail, it crashed the
// process with "interface conversion: error is *openapi.GenericOpenAPIError, not
// openapi.GenericOpenAPIError".
func TestAmfStatusChangeSubscribeSurvivesAStatusTheClientDoesNotName(t *testing.T) {
	svr := peerReturning(t, http.StatusGatewayTimeout, false)

	problem, err := AmfStatusChangeSubscribe(svr.URL, []models.Guami{})

	if err == nil {
		t.Error("err = nil, want the transport error: nothing decoded, so there is no problem " +
			"detail to report and the failure must not read as success")
	}
	if problem != nil {
		t.Errorf("problemDetails = %+v, want nil: no body decoded, so there is nothing to report", problem)
	}
}
