// Copyright (C) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package policyauthorization

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/omec-project/openapi/v2/models"
	pcfContext "github.com/omec-project/pcf/context"
)

// A PUT that creates the subscription answers 201 with the new resource's Location; the handler
// has to copy it from the producer's response onto the HTTP one.
func TestPutEventsSubscriptionForwardsTheLocationHeader(t *testing.T) {
	const appSessID = "app-location-1"

	decision := models.NewSmPolicyDecision()
	smPolicy := &pcfContext.UeSmPolicyData{
		PolicyContext:  models.NewSmPolicyContextDataWithDefaults(),
		PolicyDecision: decision,
		AppSessions:    map[string]bool{},
		PcfUe:          &pcfContext.UeContext{Supi: "imsi-208930100007487"},
	}
	ctx := models.NewAppSessionContext()
	ctx.AscReqData = *models.NewNullableAppSessionContextReqData(models.NewAppSessionContextReqData("http://af/notify", ""))
	pcfContext.PCF_Self().AppSessionPool.Store(appSessID, &pcfContext.AppSessionData{
		AppSessionId:      appSessID,
		AppSessionContext: ctx,
		SmPolicyData:      smPolicy,
	})
	t.Cleanup(func() { pcfContext.PCF_Self().AppSessionPool.Delete(appSessID) })

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/app-sessions/:appSessionId/events-subscription", HTTPUpdateEventsSubsc)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPut, "/app-sessions/"+appSessID+"/events-subscription",
		strings.NewReader(`{"events":[{"event":"`+string(models.AFEVENTPCF_PLMN_CHG)+`"}],"notifUri":"http://af/events"}`))
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusCreated, recorder.Body.String())
	}
	location := recorder.Header().Get("Location")
	if !strings.HasSuffix(location, "/app-sessions/"+appSessID+"/events-subscription") {
		t.Errorf("Location = %q, want the events-subscription resource of %s", location, appSessID)
	}
}
