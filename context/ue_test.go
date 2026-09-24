// Copyright (c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"fmt"
	"testing"
	"time"

	"github.com/omec-project/openapi/v2/models"
)

func TestIncreaseRemainGBR_IgnoresNilQosDecs(t *testing.T) {
	policy := &UeSmPolicyData{PolicyDecision: &models.SmPolicyDecision{}}

	origUL, origDL := policy.IncreaseRemainGBR("qos-1")
	if origUL != nil || origDL != nil {
		t.Fatalf("expected nil original GBR values, got %v and %v", origUL, origDL)
	}
}

// The window this closes is the one a pointer comparison cannot see. An application function
// claims a session by writing its PCC rules *into* the stored decision, which leaves the pointer
// exactly where it was — so "the pointer is still the one I computed against" is true of a claimed
// session, and storing on the strength of it discards the rules the AF just installed.
func TestStorePolicyDecisionIfUntouchedRefusesAClaimedSession(t *testing.T) {
	basedOn := &models.SmPolicyDecision{}
	replacement := &models.SmPolicyDecision{}
	policy := &UeSmPolicyData{PolicyDecision: basedOn, AppSessions: map[string]bool{}}

	// Exactly what an AF claim leaves behind: a registered app session and an untouched pointer.
	policy.AddAppSession("app-1")

	if policy.StorePolicyDecisionIfUntouched(basedOn, replacement) {
		t.Error("stored over a session an application function had claimed")
	}
	if policy.PolicyDecision != basedOn {
		t.Error("the claimed session's decision was replaced, discarding the AF's rules")
	}
}

// The other side, so the guard cannot be widened into refusing everything: an unclaimed session
// whose decision is still the one the caller computed against is stored.
func TestStorePolicyDecisionIfUntouchedStoresAnUnclaimedSession(t *testing.T) {
	basedOn := &models.SmPolicyDecision{}
	replacement := &models.SmPolicyDecision{}
	policy := &UeSmPolicyData{PolicyDecision: basedOn, AppSessions: map[string]bool{}}

	if !policy.StorePolicyDecisionIfUntouched(basedOn, replacement) {
		t.Fatal("refused an unclaimed session whose decision had not changed")
	}
	if policy.PolicyDecision != replacement {
		t.Error("reported a store that did not happen")
	}
}

// A claim arriving concurrently must not deadlock: the AF handlers hold PolicyMu while they take
// AppSessionsMu, and this takes them in that same order. Run under -race.
func TestStorePolicyDecisionIfUntouchedDoesNotDeadlockAgainstAClaim(t *testing.T) {
	basedOn := &models.SmPolicyDecision{}
	policy := &UeSmPolicyData{PolicyDecision: basedOn, AppSessions: map[string]bool{}}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := range 200 {
			// The AF handler's order: PolicyMu first, then AppSessionsMu underneath it.
			policy.PolicyMu.Lock()
			policy.AddAppSession(fmt.Sprintf("app-%d", i))
			policy.RemoveAppSession(fmt.Sprintf("app-%d", i))
			policy.PolicyMu.Unlock()
		}
	}()
	for range 200 {
		policy.StorePolicyDecisionIfUntouched(basedOn, &models.SmPolicyDecision{})
	}

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("claim and store deadlocked against each other")
	}
}
