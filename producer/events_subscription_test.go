// Copyright (C) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package producer

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"sync/atomic"
	"testing"

	"github.com/omec-project/openapi/v2/models"
	pcfContext "github.com/omec-project/pcf/context"
	"github.com/omec-project/pcf/internal/notifyevent"
)

const (
	testQosID       = testRuleID + "-qos"
	testRuleID      = "r1"
	testAfNotifyURI = "http://af/notify"
	testAfEventsURI = "http://af/events"
)

// smfCounter starts a stand-in SMF for the SM policy and counts the notifications it receives. The
// dispatcher is process-wide and unregistered by default, so the test registers it for its own
// duration; the notification is then sent synchronously.
func smfCounter(t *testing.T, smPolicy *pcfContext.UeSmPolicyData) *atomic.Int32 {
	t.Helper()
	if err := notifyevent.RegisterNotifyDispatcher(); err != nil {
		t.Fatalf("registering the notify dispatcher: %v", err)
	}
	t.Cleanup(notifyevent.UnregisterNotifyDispatcher)
	var received atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		received.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	smPolicy.PolicyContext.SetNotificationUri(srv.URL + "/nsmf-callback/sm-policies/ref-1")
	return &received
}

// appSessionOn stores an application session on a session's SM policy, with one PCC rule that has
// QoS data, and returns it.
func appSessionOn(t *testing.T, smPolicy *pcfContext.UeSmPolicyData, id string) *pcfContext.AppSessionData {
	t.Helper()

	smPolicy.PcfUe = &pcfContext.UeContext{Supi: testEstablishedSupi}
	qosDecs := map[string]*models.QosData{testQosID: models.NewQosData(testQosID)}
	smPolicy.PolicyDecision.QosDecs = &qosDecs
	rule := models.NewPccRule(testRuleID)
	rule.SetRefQosData([]string{testQosID})
	smPolicy.PolicyDecision.PccRules = map[string]*models.PccRule{testRuleID: rule}

	ctx := models.NewAppSessionContext()
	ctx.AscReqData = *models.NewNullableAppSessionContextReqData(models.NewAppSessionContextReqData(testAfNotifyURI, ""))
	appSession := &pcfContext.AppSessionData{
		AppSessionId:      id,
		AppSessionContext: ctx,
		SmPolicyData:      smPolicy,
		RelatedPccRuleIds: map[string]string{"1": testRuleID},
	}
	pcfContext.PCF_Self().AppSessionPool.Store(id, appSession)
	smPolicy.AddAppSession(id)
	t.Cleanup(func() { pcfContext.PCF_Self().AppSessionPool.Delete(id) })
	return appSession
}

// putEventsSubsc is UpdateEventsSubscContextProcedure without the Location header, which only the
// tests of the creating PUT look at.
func putEventsSubsc(id string, req models.EventsSubscReqData) (*models.EventsSubscPutData, int, *models.ProblemDetails) {
	resp, _, status, problem := UpdateEventsSubscContextProcedure(id, req)
	return resp, status, problem
}

func subscribeTo(events ...models.AfEventPcf) models.EventsSubscReqData {
	subs := make([]models.AfEventSubscription, 0, len(events))
	for _, event := range events {
		subs = append(subs, *models.NewAfEventSubscription(event))
	}
	req := models.NewEventsSubscReqData(subs)
	req.SetNotifUri(testAfEventsURI)
	return *req
}

// Updating or deleting an unrelated subscription used to prune PLMN_CH, AC_TY_CH and QOS_NOTIF
// from the session, which stops the SMF reporting serving-network and access-type changes.
func TestDeleteEventsSubscKeepsTheBaselineTriggers(t *testing.T) {
	const id = "app-baseline-1"
	smPolicy := establishedSession(t, nil, models.NewSmPolicyDecision())
	smfCounter(t, smPolicy)
	appSession := appSessionOn(t, smPolicy, id)
	appSession.Events = map[models.AfEventPcf]models.AfNotifMethod{models.AFEVENTPCF_USAGE_REPORT: ""}
	// Triggers an AF subscription asked for on top of the baseline.
	smPolicy.PolicyDecision.PolicyCtrlReqTriggers = append(smPolicy.PolicyDecision.PolicyCtrlReqTriggers,
		models.POLICYCONTROLREQUESTTRIGGER_US_RE, models.POLICYCONTROLREQUESTTRIGGER_SUCC_RES_ALLO)

	if problem := DeleteEventsSubscContextProcedure(id); problem != nil {
		t.Fatalf("unexpected problem details: %+v", problem)
	}

	got := smPolicy.PolicyDecision.PolicyCtrlReqTriggers
	for _, trigger := range pcfContext.BaselinePolicyCtrlReqTriggers {
		if !slices.Contains(got, trigger) {
			t.Errorf("baseline trigger %s was removed: triggers are now %v", trigger, got)
		}
	}
	for _, trigger := range []models.PolicyControlRequestTrigger{
		models.POLICYCONTROLREQUESTTRIGGER_US_RE, models.POLICYCONTROLREQUESTTRIGGER_SUCC_RES_ALLO,
	} {
		if slices.Contains(got, trigger) {
			t.Errorf("trigger %s only an AF subscription asked for was kept", trigger)
		}
	}
}

// A background data transfer session is stored without an SM policy; the subscription handlers
// used to lock it.
func TestEventsSubscRejectsASessionWithoutAnSmPolicy(t *testing.T) {
	const id = "app-bdt-1"
	appSession := &pcfContext.AppSessionData{
		AppSessionId:      id,
		AppSessionContext: models.NewAppSessionContext(),
		Events:            map[models.AfEventPcf]models.AfNotifMethod{models.AFEVENTPCF_PLMN_CHG: ""},
		EventUri:          testAfEventsURI,
	}
	pcfContext.PCF_Self().AppSessionPool.Store(id, appSession)
	t.Cleanup(func() { pcfContext.PCF_Self().AppSessionPool.Delete(id) })

	if problem := DeleteEventsSubscContextProcedure(id); problem == nil || problem.GetStatus() != http.StatusForbidden {
		t.Errorf("DELETE: problem = %+v, want 403", problem)
	}
	_, status, problem := putEventsSubsc(id, subscribeTo(models.AFEVENTPCF_PLMN_CHG))
	if problem == nil || status != http.StatusForbidden {
		t.Errorf("PUT: status %d, problem %+v, want 403", status, problem)
	}
	if appSession.Events == nil || appSession.EventUri == "" {
		t.Error("the stored subscription was modified although the request was rejected")
	}
}

// Enabling QoS notification control changes the QoS data the SMF holds, so it has to be sent even
// when QOS_NOTIF is already among the triggers, as it is at establishment.
func TestEventsSubscQosNotifSendsTheNewQncToTheSmf(t *testing.T) {
	const id = "app-qnc-1"
	smPolicy := establishedSession(t, nil, models.NewSmPolicyDecision())
	received := smfCounter(t, smPolicy)
	appSessionOn(t, smPolicy, id)
	if !slices.Contains(smPolicy.PolicyDecision.PolicyCtrlReqTriggers, models.POLICYCONTROLREQUESTTRIGGER_QOS_NOTIF) {
		t.Fatal("fixture: QOS_NOTIF should already be a trigger")
	}

	if _, _, problem := putEventsSubsc(id, subscribeTo(models.AFEVENTPCF_QOS_NOTIF)); problem != nil {
		t.Fatalf("unexpected problem details: %+v", problem)
	}

	if !(*smPolicy.PolicyDecision.QosDecs)[testQosID].GetQnc() {
		t.Error("Qnc was not enabled on the related QoS data")
	}
	if got := received.Load(); got != 1 {
		t.Errorf("SMF received %d notifications, want 1", got)
	}
}

// The identifier in an immediate notification is the one every later notification carries: the
// subscription resource, not the AF's own callback.
func TestEventsSubscImmediateNotificationNamesTheSubscriptionResource(t *testing.T) {
	const id = "app-uri-1"
	smPolicy := establishedSession(t, nil, models.NewSmPolicyDecision())
	appSessionOn(t, smPolicy, id)

	resp, _, problem := putEventsSubsc(id, subscribeTo(models.AFEVENTPCF_PLMN_CHG))
	if problem != nil {
		t.Fatalf("unexpected problem details: %+v", problem)
	}

	if resp.EventsNotification == nil {
		t.Fatal("no immediate notification")
	}
	want := eventsSubscriptionUri(id)
	if got := resp.EventsNotification.GetEvSubsUri(); got != want {
		t.Errorf("evSubsUri = %q, want %q", got, want)
	}
}
