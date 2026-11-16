// Copyright (c) 2026 Intel Corporation
// SPDX-FileCopyrightText: 2025 Canonical Ltd.
// SPDX-License-Identifier: Apache-2.0

package nfregistration

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/pcf/consumer"
)

// The registration logic is tested in openapi/nrfregistration. These tests check that the PCF wiring
// reaches the right consumer functions.

func waitFor(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal(msg)
}

func nonEmptyConfig() consumer.NfProfileDynamicConfig {
	return consumer.NfProfileDynamicConfig{
		Plmns: map[models.PlmnId]struct{}{{Mcc: "123", Mnc: "45"}: {}},
		Dnns:  map[string]struct{}{"internet": {}},
	}
}

func startService(t *testing.T) chan<- consumer.NfProfileDynamicConfig {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	ch := make(chan consumer.NfProfileDynamicConfig)
	go func() { defer close(done); StartNfRegistrationService(ctx, ch) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return ch
}

func TestStartNfRegistrationService_NonEmptyConfigRegistersThenEmptyConfigDeregisters(t *testing.T) {
	origRegister, origDeregister, origDiscover := consumer.SendRegisterNFInstance, consumer.SendDeregisterNFInstance, consumer.DiscoverUdr
	t.Cleanup(func() {
		consumer.SendRegisterNFInstance, consumer.SendDeregisterNFInstance, consumer.DiscoverUdr = origRegister, origDeregister, origDiscover
	})
	var registeredWith atomic.Value
	var deregistered, discovered atomic.Int32
	consumer.SendRegisterNFInstance = func(_ context.Context, cfg consumer.NfProfileDynamicConfig) (*models.NFProfile, string, error) {
		registeredWith.Store(cfg)
		return models.NewNFProfileWithDefaults(), "", nil
	}
	consumer.SendDeregisterNFInstance = func(context.Context) error {
		deregistered.Add(1)
		return nil
	}
	consumer.DiscoverUdr = func() { discovered.Add(1) }

	ch := startService(t)

	ch <- nonEmptyConfig()
	waitFor(t, func() bool { return registeredWith.Load() != nil }, "SendRegisterNFInstance was not called")
	got := registeredWith.Load().(consumer.NfProfileDynamicConfig)
	if _, ok := got.Plmns[models.PlmnId{Mcc: "123", Mnc: "45"}]; !ok || len(got.Plmns) != 1 {
		t.Errorf("registered with %+v", got)
	}
	waitFor(t, func() bool { return discovered.Load() == 1 }, "DiscoverUdr was not called for a non-empty config")

	ch <- consumer.NfProfileDynamicConfig{}
	waitFor(t, func() bool { return deregistered.Load() == 1 }, "SendDeregisterNFInstance was not called for an empty config")
	if discovered.Load() != 1 {
		t.Errorf("DiscoverUdr calls = %d, want 1 (not called for an empty config)", discovered.Load())
	}
}

func TestDeregisterNF_CallsConsumer(t *testing.T) {
	orig := consumer.SendDeregisterNFInstance
	t.Cleanup(func() { consumer.SendDeregisterNFInstance = orig })
	var called atomic.Int32
	consumer.SendDeregisterNFInstance = func(context.Context) error { called.Add(1); return nil }

	DeregisterNF()
	if called.Load() != 1 {
		t.Errorf("SendDeregisterNFInstance calls = %d, want 1", called.Load())
	}
}

func TestHeartbeatUsesSendUpdateNFInstance(t *testing.T) {
	origRegister, origUpdate, origDiscover := consumer.SendRegisterNFInstance, consumer.SendUpdateNFInstance, consumer.DiscoverUdr
	t.Cleanup(func() {
		consumer.SendRegisterNFInstance, consumer.SendUpdateNFInstance, consumer.DiscoverUdr = origRegister, origUpdate, origDiscover
	})
	var updated atomic.Int32
	profile := models.NewNFProfileWithDefaults()
	profile.SetHeartBeatTimer(1)
	consumer.SendRegisterNFInstance = func(context.Context, consumer.NfProfileDynamicConfig) (*models.NFProfile, string, error) {
		return profile, "", nil
	}
	consumer.SendUpdateNFInstance = func(_ context.Context, patch []models.PatchItem) (*models.NFProfile, *models.ProblemDetails, error) {
		updated.Add(1)
		return profile, nil, nil
	}
	consumer.DiscoverUdr = func() {}

	ch := startService(t)

	ch <- nonEmptyConfig()
	waitFor(t, func() bool { return updated.Load() >= 1 }, "heartbeat did not call SendUpdateNFInstance")
}
