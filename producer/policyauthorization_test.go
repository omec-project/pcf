// Copyright (c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package producer

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/omec-project/openapi/v2/models"
	pcfContext "github.com/omec-project/pcf/context"
	"github.com/omec-project/pcf/util"
)

func TestSendAppSessionEventNotificationUsesExactCallbackURI(t *testing.T) {
	received := make(chan models.EventsNotification, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/notify" {
			t.Fatalf("unexpected callback path %q", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Fatalf("unexpected method %q", r.Method)
		}
		var notification models.EventsNotification
		if err := json.NewDecoder(r.Body).Decode(&notification); err != nil {
			t.Fatalf("failed to decode event notification: %v", err)
		}
		received <- notification
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	appSession := &pcfContext.AppSessionData{
		AppSessionId: "app-session-1",
		EventUri:     server.URL + "/notify",
	}
	request := models.NewEventsNotification("", []models.AfEventNotification{{Event: models.AFEVENTPCF_ACCESS_TYPE_CHANGE}})

	SendAppSessionEventNotification(appSession, *request)

	select {
	case notification := <-received:
		wantEvSubsURI := util.GetResourceUri(models.SERVICENAME_NPCF_POLICYAUTHORIZATION, appSession.AppSessionId) + "/events-subscription"
		if notification.EvSubsUri != wantEvSubsURI {
			t.Fatalf("unexpected evSubsUri %q", notification.EvSubsUri)
		}
	default:
		t.Fatal("expected callback request")
	}
}

func TestSendAppSessionTerminationUsesExactCallbackURI(t *testing.T) {
	received := make(chan models.TerminationInfo, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/terminate" {
			t.Fatalf("unexpected callback path %q", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Fatalf("unexpected method %q", r.Method)
		}
		var terminationInfo models.TerminationInfo
		if err := json.NewDecoder(r.Body).Decode(&terminationInfo); err != nil {
			t.Fatalf("failed to decode termination info: %v", err)
		}
		received <- terminationInfo
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	ascReqData := models.NewAppSessionContextReqData("", "")
	ascReqData.SetNotifUri(server.URL + "/terminate")
	appSessionContext := models.NewAppSessionContext()
	appSessionContext.SetAscReqData(*ascReqData)
	appSession := &pcfContext.AppSessionData{
		AppSessionId:      "app-session-2",
		AppSessionContext: appSessionContext,
	}
	request := *models.NewTerminationInfo(models.TERMINATIONCAUSE_PDU_SESSION_TERMINATION, "")

	SendAppSessionTermination(appSession, request)

	select {
	case terminationInfo := <-received:
		wantResURI := util.GetResourceUri(models.SERVICENAME_NPCF_POLICYAUTHORIZATION, appSession.AppSessionId)
		if terminationInfo.ResUri != wantResURI {
			t.Fatalf("unexpected resUri %q", terminationInfo.ResUri)
		}
	default:
		t.Fatal("expected callback request")
	}
}
