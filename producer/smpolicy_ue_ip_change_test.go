// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
//
// SPDX-License-Identifier: Apache-2.0

package producer

import (
	"sync"
	"testing"

	"github.com/omec-project/openapi/v2"
	"github.com/omec-project/openapi/v2/models"
	pcfContext "github.com/omec-project/pcf/context"
)

const (
	testCreateIpv4 = "192.168.139.17"
	testUpfIpv4    = "192.168.100.1"
	testIpv6Prefix = "2001:db8::/64"
)

// newSessionBoundTo builds a UE with one SM policy holding testCreateIpv4, the way the create path
// leaves it, and returns the UE and the policy id the SMF would address an update to.
func newSessionBoundTo(t *testing.T, supi string) (*pcfContext.UeContext, string) {
	t.Helper()
	self := pcfContext.PCF_Self()
	ue := &pcfContext.UeContext{
		Supi:         supi,
		SmPolicyData: make(map[string]*pcfContext.UeSmPolicyData),
	}
	self.UePool.Store(supi, ue)
	t.Cleanup(func() { self.UePool.Delete(supi) })

	smPolicyID := supi + "-10"
	ctx := models.SmPolicyContextData{
		Supi:         supi,
		PduSessionId: 10,
		Dnn:          testDnn,
		SliceInfo:    testSnssai,
		Ipv4Address:  openapi.PtrString(testCreateIpv4),
	}
	policy := ue.NewUeSmPolicyData(smPolicyID, ctx, &models.SmPolicyData{})
	if policy == nil {
		t.Fatal("failed to build the SM policy fixture")
	}
	policy.PolicyDecision = &models.SmPolicyDecision{}
	return ue, smPolicyID
}

func ueIpChangeRequest(newIpv4, relIpv4 string) models.SmPolicyUpdateContextData {
	req := models.SmPolicyUpdateContextData{
		RepPolicyCtrlReqTriggers: []models.PolicyControlRequestTrigger{
			models.POLICYCONTROLREQUESTTRIGGER_UE_IP_CH,
		},
	}
	if newIpv4 != "" {
		req.Ipv4Address = openapi.PtrString(newIpv4)
	}
	if relIpv4 != "" {
		req.RelIpv4Address = openapi.PtrString(relIpv4)
	}
	return req
}

// The point of the trigger: after it, an application function binds on the address the UE actually
// has. Asserted through SMPolicyFindByIdentifiersIpv4 rather than by reading the field back,
// because binding is what the address is for and the finder is what the AF path calls.
func TestUeIpChangeRebindsTheSessionToTheNewAddress(t *testing.T) {
	ue, smPolicyID := newSessionBoundTo(t, "imsi-001010123456700")

	if _, problem := updateSmPolicyContextProcedure(ueIpChangeRequest(testUpfIpv4, testCreateIpv4), smPolicyID); problem != nil {
		t.Fatalf("update refused: %+v", problem)
	}

	if got := ue.SMPolicyFindByIdentifiersIpv4(testUpfIpv4, &testSnssai, testDnn, ""); got == nil {
		t.Errorf("the session cannot be found by the address the UE now has (%s)", testUpfIpv4)
	}
	if got := ue.SMPolicyFindByIdentifiersIpv4(testCreateIpv4, &testSnssai, testDnn, ""); got != nil {
		t.Errorf("the session is still bound to the address the SMF gave back (%s)", testCreateIpv4)
	}
}

// A report that only releases an address. Before the comparison was fixed this did nothing at all:
// both sides are *string off a decoded body, so they are never the same pointer, and the session
// stayed bound to an address the SMF had already returned to its pool -- where it can be handed to
// a different subscriber, making the stale key valid for the wrong session.
func TestUeIpChangeReleaseClearsTheStoredAddress(t *testing.T) {
	ue, smPolicyID := newSessionBoundTo(t, "imsi-001010123456701")

	if _, problem := updateSmPolicyContextProcedure(ueIpChangeRequest("", testCreateIpv4), smPolicyID); problem != nil {
		t.Fatalf("update refused: %+v", problem)
	}

	if got := ue.SMPolicyFindByIdentifiersIpv4(testCreateIpv4, &testSnssai, testDnn, ""); got != nil {
		t.Errorf("the released address %s still binds to the session", testCreateIpv4)
	}
}

// Releasing an address the session does not hold must not clear the one it does.
func TestUeIpChangeReleaseOfAnotherAddressLeavesTheSessionBound(t *testing.T) {
	ue, smPolicyID := newSessionBoundTo(t, "imsi-001010123456702")

	if _, problem := updateSmPolicyContextProcedure(ueIpChangeRequest("", "10.0.0.9"), smPolicyID); problem != nil {
		t.Fatalf("update refused: %+v", problem)
	}

	if got := ue.SMPolicyFindByIdentifiersIpv4(testCreateIpv4, &testSnssai, testDnn, ""); got == nil {
		t.Errorf("releasing an unrelated address unbound the session from %s", testCreateIpv4)
	}
}

// The race the SMF's report makes reachable. An application function binding a session and the SMF
// reporting a new address are two HTTP handlers on two goroutines, and before this change they
// touched PolicyContext.Ipv4Address with no lock in common -- the finders hold SmPolicyDataMu, the
// update handler held nothing.
//
// The loop matters as much as the goroutines: the finder walks the map and compares, so the read
// has to be reached, not merely scheduled. Run this with -race.
func TestUeIpChangeDoesNotRaceSessionBinding(t *testing.T) {
	const iterations = 200
	ue, smPolicyID := newSessionBoundTo(t, "imsi-001010123456703")

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			addr := testUpfIpv4
			if i%2 == 0 {
				addr = testCreateIpv4
			}
			if _, problem := updateSmPolicyContextProcedure(ueIpChangeRequest(addr, ""), smPolicyID); problem != nil {
				t.Errorf("update refused: %+v", problem)
				return
			}
		}
	}()

	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			ue.SMPolicyFindByIdentifiersIpv4(testUpfIpv4, &testSnssai, testDnn, "")
			ue.SMPolicyFindByIpv4(testCreateIpv4)
		}
	}()

	wg.Wait()
}

// The S-NSSAI guard in the finders, pinned on its own because it is a second and independent reason
// session binding failed: the stored slice is an Snssai and the caller's is an *Snssai, and
// reflect.DeepEqual is false for distinct types however they compare. An application function that
// named a slice — which is the ordinary case, TS 29.514 has it identify the session — could never
// bind, whatever address it supplied.
func TestSessionBindingMatchesOnTheSliceTheSessionWasCreatedWith(t *testing.T) {
	ue, _ := newSessionBoundTo(t, "imsi-001010123456704")

	if got := ue.SMPolicyFindByIdentifiersIpv4(testCreateIpv4, &testSnssai, testDnn, ""); got == nil {
		t.Error("a request naming the session's own slice did not bind")
	}
	// Still a filter, not a formality: a different slice must not match.
	other := models.Snssai{Sst: 2, Sd: openapi.PtrString("040506")}
	if got := ue.SMPolicyFindByIdentifiersIpv4(testCreateIpv4, &other, testDnn, ""); got != nil {
		t.Error("a request naming a different slice bound anyway")
	}
	// And the DNN filter still applies alongside it.
	if got := ue.SMPolicyFindByIdentifiersIpv4(testCreateIpv4, &testSnssai, "other-dnn", ""); got != nil {
		t.Error("a request naming a different DNN bound anyway")
	}
}
