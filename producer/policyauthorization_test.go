// Copyright (c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package producer

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/omec-project/openapi/v2"
	"github.com/omec-project/openapi/v2/models"
	pcfContext "github.com/omec-project/pcf/context"
	"github.com/omec-project/pcf/util"
)

func newCombinedMediaTestPolicy() *pcfContext.UeSmPolicyData {
	return &pcfContext.UeSmPolicyData{
		PolicyDecision: &models.SmPolicyDecision{
			PccRules: make(map[string]models.PccRule),
		},
		PackFiltMapToPccRuleId: make(map[string]string),
		PackFiltIdGenarator:    1,
		PccRuleIdGenarator:     1,
	}
}

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

func TestHandleCombinedMediaSubComponentsCreatesRuleAndUsesActiveStatus(t *testing.T) {
	smPolicy := newCombinedMediaTestPolicy()
	medComp := &models.MediaComponent{FStatus: models.FLOWSTATUS_REMOVED.Ptr()}
	medSubComps := []models.MediaSubComponent{
		{FNum: 1, FStatus: models.FLOWSTATUS_REMOVED.Ptr()},
		{FNum: 2, FStatus: models.FLOWSTATUS_ENABLED.Ptr()},
	}
	flowInfos := []models.FlowInformation{
		{FlowDescription: openapi.PtrString("permit out ip from any to 10.0.0.1")},
		{FlowDescription: openapi.PtrString("permit in ip from 10.0.0.1 to any")},
	}

	pccRule, problemDetails := handleCombinedMediaSubComponents(smPolicy, medComp, medSubComps, 9, flowInfos)
	if problemDetails != nil {
		t.Fatalf("unexpected problem details: %+v", problemDetails)
	}
	if pccRule == nil {
		t.Fatal("expected a PCC rule to be created")
		return
	}
	if got, want := pccRule.GetPccRuleId(), "1"; got != want {
		t.Fatalf("unexpected PCC rule ID %q, want %q", got, want)
	}
	if got := len(pccRule.FlowInfos); got != len(flowInfos) {
		t.Fatalf("unexpected flow count %d, want %d", got, len(flowInfos))
	}
	for index, flowInfo := range pccRule.FlowInfos {
		if got, want := flowInfo.GetPackFiltId(), util.GetPackFiltId(int32(1+index)); got != want {
			t.Fatalf("unexpected PackFiltId at index %d: %q, want %q", index, got, want)
		}
		if got := smPolicy.PackFiltMapToPccRuleId[flowInfo.GetPackFiltId()]; got != pccRule.GetPccRuleId() {
			t.Fatalf("unexpected PackFilt mapping for %q: %q", flowInfo.GetPackFiltId(), got)
		}
	}
	if smPolicy.PolicyDecision.TraffContDecs == nil {
		t.Fatal("expected Traffic Control data to be created")
	}
	tcData, ok := (*smPolicy.PolicyDecision.TraffContDecs)[pccRule.RefTcData[0]]
	if !ok {
		t.Fatalf("expected Traffic Control data %q to exist", pccRule.RefTcData[0])
	}
	if got, want := tcData.GetFlowStatus(), models.FLOWSTATUS_ENABLED; got != want {
		t.Fatalf("unexpected flow status %q, want %q", got, want)
	}
}

func TestHandleCombinedMediaSubComponentsReusesExistingRuleAndAddsNewFlow(t *testing.T) {
	smPolicy := newCombinedMediaTestPolicy()
	existingRule := util.CreatePccRule(7, 10, []models.FlowInformation{{
		FlowDescription: openapi.PtrString("permit out ip from any to 10.0.0.1"),
		PackFiltId:      openapi.PtrString("77"),
	}}, "")
	smPolicy.PolicyDecision.PccRules[existingRule.GetPccRuleId()] = *existingRule
	smPolicy.PackFiltMapToPccRuleId["77"] = existingRule.GetPccRuleId()
	smPolicy.PackFiltIdGenarator = 5

	flowInfos := []models.FlowInformation{
		{FlowDescription: openapi.PtrString("permit out ip from any to 10.0.0.1")},
		{FlowDescription: openapi.PtrString("permit in ip from 10.0.0.1 to any")},
	}

	pccRule, problemDetails := handleCombinedMediaSubComponents(
		smPolicy,
		&models.MediaComponent{},
		[]models.MediaSubComponent{{FNum: 1, FStatus: models.FLOWSTATUS_ENABLED.Ptr()}},
		9,
		flowInfos,
	)
	if problemDetails != nil {
		t.Fatalf("unexpected problem details: %+v", problemDetails)
	}
	if got, want := pccRule.GetPccRuleId(), existingRule.GetPccRuleId(); got != want {
		t.Fatalf("unexpected reused PCC rule ID %q, want %q", got, want)
	}
	if got := len(pccRule.FlowInfos); got != 2 {
		t.Fatalf("unexpected flow count %d, want 2", got)
	}
	if got, want := pccRule.FlowInfos[1].GetPackFiltId(), "5"; got != want {
		t.Fatalf("unexpected new PackFiltId %q, want %q", got, want)
	}
	if got := smPolicy.PackFiltMapToPccRuleId["5"]; got != existingRule.GetPccRuleId() {
		t.Fatalf("unexpected PackFilt mapping for new flow: %q", got)
	}
	if got := smPolicy.PccRuleIdGenarator; got != 1 {
		t.Fatalf("expected PCC rule generator to remain unchanged, got %d", got)
	}
}

func TestGetMaxPccRuleIdNum(t *testing.T) {
	tests := []struct {
		name     string
		pccRules map[string]models.PccRule
		want     int32
	}{
		{
			name: "prefers highest full numeric id",
			pccRules: map[string]models.PccRule{
				"0":     {},
				"12":    {},
				"1-foo": {},
			},
			want: 12,
		},
		{
			name: "accepts legacy prefixed ids",
			pccRules: map[string]models.PccRule{
				"PccRuleId-0": {},
				"PccRuleId-9": {},
			},
			want: 9,
		},
		{
			name: "falls back when no numeric ids found",
			pccRules: map[string]models.PccRule{
				"rule-a": {},
				"rule-b": {},
			},
			want: 2,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := getMaxPccRuleIdNum(tc.pccRules); got != tc.want {
				t.Fatalf("getMaxPccRuleIdNum() = %d, want %d", got, tc.want)
			}
		})
	}
}
