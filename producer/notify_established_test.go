// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package producer

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/omec-project/openapi/v2"
	"github.com/omec-project/openapi/v2/models"
	pcfContext "github.com/omec-project/pcf/context"
	"github.com/omec-project/pcf/factory"
	"github.com/omec-project/pcf/internal/notifyevent"
	"github.com/omec-project/pcf/polling"
	"github.com/omec-project/pcf/util"
)

// Literals repeated across the tables below; goconst asks for names, and the package already
// names the rule and QoS identifiers in smpolicy_test.go.
const (
	testSessionAmbr   = "50 Mbps"
	testAppSessionID  = "app-session-1"
	testNotifySession = "session"
)

func decisionWithArp(levels ...int32) *models.SmPolicyDecision {
	qosDecs := map[string]models.QosData{}
	for i, level := range levels {
		qosDecs[string(rune('a'+i))] = models.QosData{
			Arp: &models.Arp{PriorityLevel: *openapi.NewNullableInt32(openapi.PtrInt32(level))},
		}
	}
	d := &models.SmPolicyDecision{}
	d.SetQosDecs(qosDecs)
	return d
}

// TS 23.501 clause 5.7.2.2: the ARP priority range is 1 to 15 with 1 as the highest. Sorting the
// wrong way would pace the least important sites first, which is the opposite of what an operator
// re-prioritising during an incident is asking for.
func TestArpPriorityTakesTheMostImportantFlow(t *testing.T) {
	tests := []struct {
		name     string
		decision *models.SmPolicyDecision
		want     int32
	}{
		{"single flow", decisionWithArp(5), 5},
		{"most important of several", decisionWithArp(9, 2, 14), 2},
		{"highest possible", decisionWithArp(1, 15), 1},
		{"no ARP anywhere sorts last", decisionWithArp(), 16},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := defaultQosArpPriority(tc.decision); got != tc.want {
				t.Errorf("arp priority = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestPacedFanOutIsOrderedHighestPriorityFirst(t *testing.T) {
	pending := []pendingNotification{
		{smPolicyID: "low", arpPriority: 12},
		{smPolicyID: "highest", arpPriority: 1},
		{smPolicyID: "middle", arpPriority: 6},
		{smPolicyID: "none", arpPriority: 16},
	}

	sortByPriority(pending)

	want := []string{"highest", "middle", "low", "none"}
	for i, id := range want {
		if pending[i].smPolicyID != id {
			t.Fatalf("position %d = %q, want %q — ARP 1 is the highest priority, so ascending",
				i, pending[i].smPolicyID, id)
		}
	}
}

// Sessions at equal priority keep their relative order, so a slice-wide change does not reshuffle
// subscribers arbitrarily between one poll and the next.
func TestEqualPrioritiesKeepTheirOrder(t *testing.T) {
	pending := []pendingNotification{
		{smPolicyID: "first", arpPriority: 5},
		{smPolicyID: "second", arpPriority: 5},
		{smPolicyID: "third", arpPriority: 5},
	}

	sortByPriority(pending)

	for i, id := range []string{"first", "second", "third"} {
		if pending[i].smPolicyID != id {
			t.Errorf("position %d = %q, want %q", i, pending[i].smPolicyID, id)
		}
	}
}

// establishedSession puts one session in the UE pool with the decision it was given at
// establishment, so a recompute has something to compare against.
func establishedSession(t *testing.T, sessionAmbr *models.Ambr, given *models.SmPolicyDecision) *pcfContext.UeSmPolicyData {
	t.Helper()

	// No per-IMSI session rules configured, which is the ordinary case and the branch that builds
	// the session rule from the subscribed AMBR.
	originalRules := polling.GetImsiSessionRules
	polling.GetImsiSessionRules = func(string, string) (map[string]*models.SessionRule, error) {
		return nil, errors.New("no imsi session rules configured")
	}
	t.Cleanup(func() { polling.GetImsiSessionRules = originalRules })

	supi := "imsi-208930100007487"
	smPolicyID := supi + "-10"
	sst := int32(1)
	sd := "010203"

	ue := &pcfContext.UeContext{Supi: supi, SmPolicyData: map[string]*pcfContext.UeSmPolicyData{}}
	ctx := &models.SmPolicyContextData{
		Supi:            supi,
		PduSessionId:    10,
		Dnn:             "internet",
		SliceInfo:       models.Snssai{Sst: sst, Sd: openapi.PtrString(sd)},
		NotificationUri: "http://smf:29502/nsmf-callback",
		SubsSessAmbr:    sessionAmbr,
		// The SMF always supplies this at policy-create, and the recompute reads back the same
		// stored context — so a session that established successfully always has one here.
		SubsDefQos: &models.SubscribedDefaultQos{Var5qi: 9, Arp: models.Arp{
			PriorityLevel: *openapi.NewNullableInt32(openapi.PtrInt32(8)),
		}},
	}
	// Stamped the way createSmPolicyContextProcedure stamps it. These fields are per-session and
	// no rebuild from configuration can reproduce them: SuppFeat is the result of negotiating with
	// the SMF that created the session, PolicyCtrlReqTriggers is what that SMF reports on, and
	// Online came from the subscriber's UDR record. A fixture holding an empty decision cannot see
	// them being dropped, which is exactly how it was missed.
	given.SuppFeat = openapi.PtrString("0f")
	given.PolicyCtrlReqTriggers = util.PolicyControlReqTrigToArray(0x40780f)
	given.Online = openapi.PtrBool(true)

	smPolicy := &pcfContext.UeSmPolicyData{PolicyContext: ctx, PolicyDecision: given}
	ue.SmPolicyData[smPolicyID] = smPolicy
	pcfContext.PCF_Self().UePool.Store(supi, ue)

	t.Cleanup(func() { pcfContext.PCF_Self().UePool.Delete(supi) })
	return smPolicy
}

// runFanOut drives the whole trigger — recompute and delivery — with a sender that records what
// the SMF would have received and answers however the caller says.
//
// The tests go through delivery rather than stopping at the recompute because that is where the
// stored decision is now written. A test that asserted on stored state after recomputing alone
// would be asserting on a step that deliberately does not touch it.
func runFanOut(t *testing.T, sendResult error) []models.SmPolicyNotification {
	t.Helper()

	var sent []models.SmPolicyNotification
	originalSender := sendNotification
	sendNotification = func(_ string, request *models.SmPolicyNotification) error {
		if sendResult == nil {
			sent = append(sent, *request)
		}
		return sendResult
	}
	t.Cleanup(func() { sendNotification = originalSender })

	// Unpaced. The interval exists to protect the air interface, and nothing here is on the air.
	originalConfig := factory.PcfConfig
	factory.PcfConfig = factory.Config{Configuration: &factory.Configuration{
		PolicyNotificationRate: 100000,
	}}
	t.Cleanup(func() { factory.PcfConfig = originalConfig })

	dispatchPaced(recomputeChangedSessions())
	return sent
}

// A slice policy edit must reach a session that is already running, rather than waiting for the
// subscriber to re-establish.
func TestPolicyRuleChangeReachesAnEstablishedSession(t *testing.T) {
	original := getSlicePccPolicy
	t.Cleanup(func() { getSlicePccPolicy = original })

	getSlicePccPolicy = func(models.Snssai) *polling.PccPolicy {
		return &polling.PccPolicy{
			PccRules: map[string]*models.PccRule{testPccRuleId1: {PccRuleId: testPccRuleId1, Precedence: openapi.PtrInt32(200)}},
			QosDecs:  map[string]*models.QosData{testQosId1: {QosId: testQosId1, Var5qi: openapi.PtrInt32(10)}},
		}
	}

	// The session was given an empty decision, so anything the new policy produces is a change.
	smPolicy := establishedSession(t, nil, &models.SmPolicyDecision{})

	sent := runFanOut(t, nil)

	if len(sent) != 1 {
		t.Fatalf("notifications sent = %d, want the established session to be told", len(sent))
	}
	if len(sent[0].SmPolicyDecision.GetPccRules()) == 0 {
		t.Error("the notification carried no PCC rules, so the SMF was told nothing useful")
	}
	if smPolicy.PolicyDecision == nil || len(smPolicy.PolicyDecision.GetPccRules()) == 0 {
		t.Error("the session's stored decision must be updated once the SMF has been told")
	}
}

// A change that leaves a session's decision alone must signal nothing. The cost of a needless
// notification is a radio reconfiguration, not this element's work.
func TestUnchangedDecisionSignalsNothing(t *testing.T) {
	original := getSlicePccPolicy
	t.Cleanup(func() { getSlicePccPolicy = original })

	getSlicePccPolicy = func(models.Snssai) *polling.PccPolicy {
		return &polling.PccPolicy{
			PccRules: map[string]*models.PccRule{testPccRuleId1: {PccRuleId: testPccRuleId1}},
			QosDecs:  map[string]*models.QosData{testQosId1: {QosId: testQosId1}},
		}
	}

	// Establish, then run the trigger twice: the second pass has nothing to do.
	establishedSession(t, nil, &models.SmPolicyDecision{})
	if first := runFanOut(t, nil); len(first) != 1 {
		t.Fatalf("first fan-out sent %d, want the initial difference to be seen", len(first))
	}

	second := runFanOut(t, nil)

	if len(second) != 0 {
		t.Errorf("second fan-out sent %d, want nothing: the policy did not change between them", len(second))
	}
}

// Session-AMBR cannot be changed mid-session, and this pins why rather than leaving it to a
// reading of the code. It reaches the PCF from the SMF at policy-create time, sourced from
// subscription data, and is not part of the polled configuration — so a recompute reads back the
// value the session already had, whatever the slice policy now says.
func TestSessionAmbrIsNotChangedByAPolicyEdit(t *testing.T) {
	original := getSlicePccPolicy
	t.Cleanup(func() { getSlicePccPolicy = original })

	getSlicePccPolicy = func(models.Snssai) *polling.PccPolicy {
		return &polling.PccPolicy{
			PccRules: map[string]*models.PccRule{testPccRuleId1: {PccRuleId: testPccRuleId1}},
			QosDecs:  map[string]*models.QosData{testQosId1: {QosId: testQosId1}},
		}
	}

	subscribed := &models.Ambr{Uplink: testSessionAmbr, Downlink: testSessionAmbr}
	smPolicy := establishedSession(t, subscribed, &models.SmPolicyDecision{})

	recomputeChangedSessions()

	for _, rule := range smPolicy.PolicyDecision.GetSessRules() {
		ambr := rule.GetAuthSessAmbr()
		if ambr.Uplink != testSessionAmbr || ambr.Downlink != testSessionAmbr {
			t.Errorf("session AMBR = %s/%s, want the subscribed value: a policy edit cannot change it",
				ambr.Uplink, ambr.Downlink)
		}
	}
}

// The decision a session holds is not only the slice policy: the create path negotiates supported
// features with the SMF, tells it which triggers to report, and carries charging flags from the
// subscriber's UDR record. A policy edit must leave all of that standing.
//
// Rebuilding the whole decision from configuration drops every one of these, and because the
// stored decision always has them and a rebuild never does, it also makes each session differ from
// itself on every edit — so the "did anything change" test stops meaning anything and every
// session gets notified with a downgraded policy.
func TestPerSessionDecisionStateSurvivesAPolicyEdit(t *testing.T) {
	original := getSlicePccPolicy
	t.Cleanup(func() { getSlicePccPolicy = original })

	getSlicePccPolicy = func(models.Snssai) *polling.PccPolicy {
		return &polling.PccPolicy{
			PccRules: map[string]*models.PccRule{testPccRuleId1: {PccRuleId: testPccRuleId1, Precedence: openapi.PtrInt32(200)}},
			QosDecs:  map[string]*models.QosData{testQosId1: {QosId: testQosId1, Var5qi: openapi.PtrInt32(10)}},
		}
	}

	smPolicy := establishedSession(t, nil, &models.SmPolicyDecision{})
	wantTriggers := len(smPolicy.PolicyDecision.PolicyCtrlReqTriggers)

	if sent := runFanOut(t, nil); len(sent) != 1 {
		t.Fatalf("notifications sent = %d, want the slice policy change to be seen", len(sent))
	}

	got := smPolicy.PolicyDecision
	if got.GetSuppFeat() != "0f" {
		t.Errorf("SuppFeat = %q, want it preserved: it was negotiated with the SMF, not derived from configuration", got.GetSuppFeat())
	}
	if len(got.PolicyCtrlReqTriggers) != wantTriggers {
		t.Errorf("PolicyCtrlReqTriggers = %d, want %d preserved: dropping them stops the SMF reporting the events this element relies on",
			len(got.PolicyCtrlReqTriggers), wantTriggers)
	}
	if !got.GetOnline() {
		t.Error("Online was lost, so the session's charging flags were reset by an unrelated policy edit")
	}
	// And the slice-derived part did move, so this is not passing by doing nothing.
	if len(got.GetPccRules()) == 0 {
		t.Error("the new slice policy did not reach the session")
	}
}

// A session an application function is managing is left alone. The AF installs its own PCC rules
// into the same decision and nothing records which entries are the AF's, so replacing the
// slice-derived part would take them with it — stranding an app-session that still references them.
func TestAfManagedSessionIsLeftAlone(t *testing.T) {
	original := getSlicePccPolicy
	t.Cleanup(func() { getSlicePccPolicy = original })

	getSlicePccPolicy = func(models.Snssai) *polling.PccPolicy {
		return &polling.PccPolicy{
			PccRules: map[string]*models.PccRule{testPccRuleId1: {PccRuleId: testPccRuleId1}},
			QosDecs:  map[string]*models.QosData{testQosId1: {QosId: testQosId1}},
		}
	}

	afRule := map[string]models.PccRule{"af-installed": {PccRuleId: "af-installed", AppId: openapi.PtrString("ims")}}
	given := &models.SmPolicyDecision{}
	given.SetPccRules(afRule)
	smPolicy := establishedSession(t, nil, given)
	smPolicy.AppSessions = map[string]bool{testAppSessionID: true}

	pending := recomputeChangedSessions()

	if len(pending) != 0 {
		t.Errorf("pending = %d, want 0: an AF-managed session must not be recomputed", len(pending))
	}
	if _, ok := smPolicy.PolicyDecision.GetPccRules()["af-installed"]; !ok {
		t.Error("the AF-installed PCC rule was removed by an operator policy edit")
	}
}

// A session with no notification URI must be left untouched rather than updated and skipped. If
// its stored decision moved and no notification could be sent, the next comparison would match and
// the discrepancy would never be visible again — the session would sit on a policy it was never
// told about, and nothing would say so.
func TestSessionWithNoNotificationUriIsNotSilentlyUpdated(t *testing.T) {
	original := getSlicePccPolicy
	t.Cleanup(func() { getSlicePccPolicy = original })

	getSlicePccPolicy = func(models.Snssai) *polling.PccPolicy {
		return &polling.PccPolicy{
			PccRules: map[string]*models.PccRule{testPccRuleId1: {PccRuleId: testPccRuleId1}},
			QosDecs:  map[string]*models.QosData{testQosId1: {QosId: testQosId1}},
		}
	}

	smPolicy := establishedSession(t, nil, &models.SmPolicyDecision{})
	smPolicy.PolicyContext.NotificationUri = ""

	pending := recomputeChangedSessions()

	if len(pending) != 0 {
		t.Errorf("pending = %d, want 0", len(pending))
	}
	if len(smPolicy.PolicyDecision.GetPccRules()) != 0 {
		t.Error("the stored decision was updated for a session that cannot be notified, so the change is now invisible")
	}
}

// A fan-out that cannot start must not have already moved the sessions.
//
// Reported on the pull request. Recomputing writes each changed session's new decision into the
// context; doing that and then finding the in-flight guard held would leave the sessions holding
// decisions the SMF was never told about — and because the next comparison then matches, the
// change would be invisible from then on. The warning promising it would be "picked up by the next
// change" described the one thing that could not happen.
func TestAFanOutThatCannotStartLeavesTheSessionsAlone(t *testing.T) {
	original := getSlicePccPolicy
	t.Cleanup(func() { getSlicePccPolicy = original })
	getSlicePccPolicy = func(models.Snssai) *polling.PccPolicy {
		return &polling.PccPolicy{
			PccRules: map[string]*models.PccRule{testPccRuleId1: {PccRuleId: testPccRuleId1, Precedence: openapi.PtrInt32(200)}},
			QosDecs:  map[string]*models.QosData{testQosId1: {QosId: testQosId1, Var5qi: openapi.PtrInt32(10)}},
		}
	}

	smPolicy := establishedSession(t, nil, &models.SmPolicyDecision{})

	// Another fan-out is already running.
	if !inFlight.CompareAndSwap(false, true) {
		t.Fatal("the guard was already held at the start of the test")
	}
	t.Cleanup(func() { inFlight.Store(false) })

	NotifyEstablishedSessions()

	if len(smPolicy.PolicyDecision.GetPccRules()) != 0 {
		t.Error("the session's decision was updated by a fan-out that never ran; the SMF was not told and the next comparison will match, so the change is now invisible")
	}
}

// Iterating the session map while sessions are created and released must not be a fatal runtime
// error.
//
// Reported on the pull request. The map is a plain Go map: the poll loop iterates it periodically
// while request handlers insert and delete. That is "concurrent map iteration and map write",
// which is not recoverable. The race detector catches the unsynchronised access; without the
// snapshot this test panics outright.
func TestRecomputeToleratesSessionsBeingCreatedAndReleased(t *testing.T) {
	original := getSlicePccPolicy
	t.Cleanup(func() { getSlicePccPolicy = original })
	getSlicePccPolicy = func(models.Snssai) *polling.PccPolicy {
		return &polling.PccPolicy{
			PccRules: map[string]*models.PccRule{testPccRuleId1: {PccRuleId: testPccRuleId1}},
			QosDecs:  map[string]*models.QosData{testQosId1: {QosId: testQosId1}},
		}
	}

	establishedSession(t, nil, &models.SmPolicyDecision{})
	ue, _ := pcfContext.PCF_Self().UePool.Load("imsi-208930100007487")
	ueCtx := ue.(*pcfContext.UeContext)

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			key := "churn-" + string(rune('a'+i%26))
			ueCtx.SmPolicyDataMu.Lock()
			ueCtx.SmPolicyData[key] = nil
			delete(ueCtx.SmPolicyData, key)
			ueCtx.SmPolicyDataMu.Unlock()
		}
	}()

	for i := 0; i < 200; i++ {
		recomputeChangedSessions()
	}

	close(stop)
	<-done
}

// simplePolicy installs a slice policy that differs from an empty decision, which is all the
// tests below need — they are about what happens to the notification, not what is in it.
func simplePolicy(t *testing.T) {
	t.Helper()
	original := getSlicePccPolicy
	t.Cleanup(func() { getSlicePccPolicy = original })
	getSlicePccPolicy = func(models.Snssai) *polling.PccPolicy {
		return &polling.PccPolicy{
			PccRules: map[string]*models.PccRule{testPccRuleId1: {PccRuleId: testPccRuleId1, Precedence: openapi.PtrInt32(200)}},
			QosDecs:  map[string]*models.QosData{testQosId1: {QosId: testQosId1, Var5qi: openapi.PtrInt32(10)}},
		}
	}
}

// unpaced removes the rate bound for a test that calls dispatchPaced directly.
func unpaced(t *testing.T) {
	t.Helper()
	original := factory.PcfConfig
	factory.PcfConfig = factory.Config{Configuration: &factory.Configuration{
		PolicyNotificationRate: 100000,
	}}
	t.Cleanup(func() { factory.PcfConfig = original })
}

// A notification the SMF never received must not be recorded as delivered.
//
// This is the one that makes the trigger safe to suppress repeats on. Because the next fan-out
// compares against the stored decision, storing before delivery turns a dropped notification into
// a permanent divergence: the session stays on its old policy, the PCF believes otherwise, and
// the difference that would drive a retry has been erased. The application function path can get
// away with storing first because an AF can post its app-session again; nothing re-posts a
// configuration edit.
func TestAFailedDeliveryIsRetriedOnTheNextChange(t *testing.T) {
	simplePolicy(t)
	smPolicy := establishedSession(t, nil, &models.SmPolicyDecision{})
	before := smPolicy.PolicyDecision

	if sent := runFanOut(t, errors.New("connection refused")); len(sent) != 0 {
		t.Fatalf("the sender was made to fail but %d notifications were recorded as sent", len(sent))
	}

	if smPolicy.PolicyDecision != before {
		t.Fatal("the stored decision moved even though the SMF never received it; the next comparison now matches and the change can never be retried")
	}

	// The proof that it is retried, not merely un-stored.
	if sent := runFanOut(t, nil); len(sent) != 1 {
		t.Errorf("the next fan-out sent %d, want the undelivered session to be tried again", len(sent))
	}
	if len(smPolicy.PolicyDecision.GetPccRules()) == 0 {
		t.Error("the retry succeeded but the decision was still not recorded")
	}
}

// A dead SMF must not cost one client timeout per session. With a thousand established sessions
// and a ten-second timeout, working through the whole list would take hours to discover what the
// first few attempts already showed.
func TestAFanOutGivesUpOnAnSmfThatIsNotAnswering(t *testing.T) {
	unpaced(t)

	attempts := 0
	original := sendNotification
	sendNotification = func(string, *models.SmPolicyNotification) error {
		attempts++
		return errors.New("connection refused")
	}
	t.Cleanup(func() { sendNotification = original })

	pending := make([]pendingNotification, 50)
	for i := range pending {
		smPolicy := &pcfContext.UeSmPolicyData{PolicyDecision: &models.SmPolicyDecision{}}
		pending[i] = pendingNotification{
			smPolicyID: testNotifySession,
			smPolicy:   smPolicy,
			basedOn:    smPolicy.PolicyDecision,
			decision:   &models.SmPolicyDecision{},
		}
	}

	dispatchPaced(pending)

	if attempts != maxConsecutiveNotifyFailures {
		t.Errorf("attempts = %d, want %d: a run of failures means the far end is down, not that these sessions were unlucky",
			attempts, maxConsecutiveNotifyFailures)
	}
}

// One failure in the middle is not a dead SMF, and the sessions after it must still be told.
func TestAnIsolatedFailureDoesNotStopTheFanOut(t *testing.T) {
	unpaced(t)

	attempts := 0
	original := sendNotification
	sendNotification = func(string, *models.SmPolicyNotification) error {
		attempts++
		if attempts == 2 {
			return errors.New("transient")
		}
		return nil
	}
	t.Cleanup(func() { sendNotification = original })

	pending := make([]pendingNotification, 5)
	stored := make([]*pcfContext.UeSmPolicyData, 5)
	for i := range pending {
		stored[i] = &pcfContext.UeSmPolicyData{PolicyDecision: &models.SmPolicyDecision{}}
		pending[i] = pendingNotification{
			smPolicyID: testNotifySession,
			smPolicy:   stored[i],
			basedOn:    stored[i].PolicyDecision,
			decision:   &models.SmPolicyDecision{},
		}
	}
	wasNotDelivered := stored[1].PolicyDecision

	dispatchPaced(pending)

	if attempts != 5 {
		t.Errorf("attempts = %d, want all 5: one failure is not grounds for abandoning the rest", attempts)
	}
	if stored[1].PolicyDecision != wasNotDelivered {
		t.Error("the session whose notification failed was recorded as delivered")
	}
	for _, i := range []int{0, 2, 3, 4} {
		if stored[i].PolicyDecision == nil || stored[i].PolicyDecision == pending[i].basedOn {
			t.Errorf("session %d was delivered but not recorded", i)
		}
	}
}

// Pacing means a session can wait minutes in the queue, and an application function that claims it
// meanwhile installs its PCC rules into the very decision this notification would replace. The
// AF check at recompute time is not enough on its own.
func TestASessionClaimedWhileQueuedIsNotOverwritten(t *testing.T) {
	unpaced(t)

	sent := 0
	original := sendNotification
	sendNotification = func(string, *models.SmPolicyNotification) error {
		sent++
		return nil
	}
	t.Cleanup(func() { sendNotification = original })

	smPolicy := &pcfContext.UeSmPolicyData{PolicyDecision: &models.SmPolicyDecision{}}
	pending := []pendingNotification{{
		smPolicyID: "claimed",
		smPolicy:   smPolicy,
		basedOn:    smPolicy.PolicyDecision,
		decision:   &models.SmPolicyDecision{},
	}}

	// The AF arrives after the session was queued and before its turn came round.
	smPolicy.AppSessions = map[string]bool{testAppSessionID: true}

	dispatchPaced(pending)

	if sent != 0 {
		t.Error("an AF-managed session was told to replace its policy; the AF's rules would go with it")
	}
}

// The same guard for the other way a queued session goes stale: something replaced its decision
// outright, so the merge this notification carries was computed from state that no longer exists.
func TestAReplacedDecisionIsNotOverwrittenByAQueuedNotification(t *testing.T) {
	unpaced(t)

	sent := 0
	original := sendNotification
	sendNotification = func(string, *models.SmPolicyNotification) error {
		sent++
		return nil
	}
	t.Cleanup(func() { sendNotification = original })

	smPolicy := &pcfContext.UeSmPolicyData{PolicyDecision: &models.SmPolicyDecision{}}
	pending := []pendingNotification{{
		smPolicyID: "replaced",
		smPolicy:   smPolicy,
		basedOn:    smPolicy.PolicyDecision,
		decision:   &models.SmPolicyDecision{},
	}}

	replacement := &models.SmPolicyDecision{}
	smPolicy.PolicyDecision = replacement

	dispatchPaced(pending)

	if sent != 0 {
		t.Error("a notification computed from a decision that has since been replaced was sent anyway")
	}
	if smPolicy.PolicyDecision != replacement {
		t.Error("the queued notification overwrote the newer decision")
	}
}

// The configuration poll loop must not wait for the fan-out, recompute included.
//
// The poll loop is a single serial goroutine and it is how the PCF sees every configuration
// change. Recomputing a session's decision fetches its session rules from the webconsole — one
// HTTP GET per established session, five second timeout each — so doing it inline would blind the
// PCF for as long as it took, and a degraded webconsole would be both the cause and the thing that
// could no longer be polled.
func TestThePollLoopIsNotBlockedByTheFanOut(t *testing.T) {
	simplePolicy(t)
	unpaced(t)

	release := make(chan struct{})
	originalRules := polling.GetImsiSessionRules
	polling.GetImsiSessionRules = func(string, string) (map[string]*models.SessionRule, error) {
		<-release
		return nil, errors.New("no imsi session rules configured")
	}
	t.Cleanup(func() { polling.GetImsiSessionRules = originalRules })

	finished := make(chan struct{})
	originalSender := sendNotification
	sendNotification = func(string, *models.SmPolicyNotification) error {
		close(finished)
		return nil
	}
	t.Cleanup(func() { sendNotification = originalSender })

	// establishedSession installs its own stub, so it has to be set up before ours takes over.
	establishedSession(t, nil, &models.SmPolicyDecision{})
	polling.GetImsiSessionRules = func(string, string) (map[string]*models.SessionRule, error) {
		<-release
		return nil, errors.New("no imsi session rules configured")
	}

	returned := make(chan struct{})
	go func() {
		NotifyEstablishedSessions()
		close(returned)
	}()

	select {
	case <-returned:
	case <-time.After(2 * time.Second):
		t.Fatal("NotifyEstablishedSessions did not return while a recompute was in progress; the poll loop is blocked behind per-session webconsole fetches")
	}

	close(release)
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("the fan-out never delivered anything after the recompute was released")
	}

	// Let the goroutine clear the in-flight guard before the stubs are restored.
	for range 100 {
		if !inFlight.Load() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Error("the in-flight guard was never released")
}

// Stale sessions must not abandon a fan-out that is otherwise healthy.
//
// The abandonment bound exists to stop the PCF spending a client timeout per session against an
// SMF that is not answering. A session the SMF no longer holds is a different thing entirely: it
// answers 404 immediately, costs nothing, and says nothing about the other sessions. Counting
// those toward the streak would let three stale sessions strand every healthy session behind them
// — the opposite of what the bound is for.
func TestStaleSessionsDoNotAbandonTheFanOut(t *testing.T) {
	unpaced(t)

	attempts := 0
	original := sendNotification
	sendNotification = func(uri string, _ *models.SmPolicyNotification) error {
		attempts++
		if attempts <= 3 {
			return fmt.Errorf("%w: SMF answered 404 Not Found", notifyevent.ErrSessionRejected)
		}
		return nil
	}
	t.Cleanup(func() { sendNotification = original })

	pending := make([]pendingNotification, 6)
	stored := make([]*pcfContext.UeSmPolicyData, 6)
	for i := range pending {
		stored[i] = &pcfContext.UeSmPolicyData{PolicyDecision: &models.SmPolicyDecision{}}
		pending[i] = pendingNotification{
			smPolicyID: testNotifySession,
			smPolicy:   stored[i],
			basedOn:    stored[i].PolicyDecision,
			decision:   &models.SmPolicyDecision{},
		}
	}

	dispatchPaced(pending)

	if attempts != 6 {
		t.Errorf("attempts = %d, want all 6: three stale sessions are not evidence that the SMF is down", attempts)
	}
	for _, i := range []int{3, 4, 5} {
		if stored[i].PolicyDecision == pending[i].basedOn {
			t.Errorf("healthy session %d was never told, because stale sessions ahead of it abandoned the fan-out", i)
		}
	}
}
