// Copyright (C) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package producer

import (
	"net/http"
	"testing"

	"github.com/omec-project/openapi/v2/models"
	pcfContext "github.com/omec-project/pcf/context"
	"github.com/omec-project/util/httpwrapper"
)

// The routers (smpolicy/ and policyauthorization/) put the path parameter in the request under
// "smPolicyId" and "appSessionId". A handler that reads any other spelling gets an empty id and
// answers 404 for a resource that exists, so these tests pass the parameter exactly as the
// routers do and require that the existing resource is found.

func TestGetSmPolicyContextFindsTheSessionByTheRouterParameter(t *testing.T) {
	establishedSession(t, nil, models.NewSmPolicyDecision())

	response := HandleGetSmPolicyContextRequest(&httpwrapper.Request{
		Params: map[string]string{"smPolicyId": testEstablishedSupi + "-10"},
	})

	if response.Status != http.StatusOK {
		t.Fatalf("status = %d, want %d: body %+v", response.Status, http.StatusOK, response.Body)
	}
}

// storedAppSession registers an application session with an events subscription on an
// established SM policy and returns it with its id.
func storedAppSession(t *testing.T) (string, *pcfContext.AppSessionData) {
	t.Helper()

	smPolicy := establishedSession(t, nil, models.NewSmPolicyDecision())
	smPolicy.PcfUe = &pcfContext.UeContext{Supi: testEstablishedSupi}

	const appSessID = "app-param-key-1"
	reqData := models.NewAppSessionContextReqData("http://af/notify", "")
	reqData.EvSubsc = models.NewEventsSubscReqData(nil)
	ctx := models.NewAppSessionContext()
	ctx.AscReqData = *models.NewNullableAppSessionContextReqData(reqData)
	appSession := &pcfContext.AppSessionData{
		AppSessionId:      appSessID,
		AppSessionContext: ctx,
		SmPolicyData:      smPolicy,
		RelatedPccRuleIds: map[string]string{},
		Events:            map[models.AfEventPcf]models.AfNotifMethod{},
		EventUri:          "http://af/notify",
	}
	pcfContext.PCF_Self().AppSessionPool.Store(appSessID, appSession)
	t.Cleanup(func() { pcfContext.PCF_Self().AppSessionPool.Delete(appSessID) })
	return appSessID, appSession
}

func TestDeleteEventsSubscFindsTheAppSessionByTheRouterParameter(t *testing.T) {
	appSessID, appSession := storedAppSession(t)

	response := HandleDeleteEventsSubscContext(&httpwrapper.Request{
		Params: map[string]string{"appSessionId": appSessID},
	})

	if response.Status == http.StatusNotFound {
		t.Fatalf("existing app session reported as not found: body %+v", response.Body)
	}
	if appSession.Events != nil || appSession.EventUri != "" {
		t.Errorf("events subscription was not removed: events=%v uri=%q", appSession.Events, appSession.EventUri)
	}
}

func TestUpdateEventsSubscFindsTheAppSessionByTheRouterParameter(t *testing.T) {
	appSessID, appSession := storedAppSession(t)
	appSession.Events = nil

	reqData := models.NewEventsSubscReqData(nil)
	reqData.SetNotifUri("http://af/events")
	response := HandleUpdateEventsSubscContext(&httpwrapper.Request{
		Params: map[string]string{"appSessionId": appSessID},
		Body:   *reqData,
	})

	if response.Status == http.StatusNotFound {
		t.Fatalf("existing app session reported as not found: body %+v", response.Body)
	}
	if appSession.EventUri != "http://af/events" {
		t.Errorf("EventUri = %q, want the notification URI from the request", appSession.EventUri)
	}
}
