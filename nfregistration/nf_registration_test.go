// Copyright (c) 2026 Intel Corporation
// SPDX-FileCopyrightText: 2025 Canonical Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//
/*
 * NRF Registration Unit Tests
 *
 */
package nfregistration

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/omec-project/openapi/v2"
	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/pcf/consumer"
)

func startRegistrationServiceForTest(t *testing.T, ch <-chan consumer.NfProfileDynamicConfig) (context.CancelFunc, <-chan struct{}) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		StartNfRegistrationService(ctx, ch)
	}()
	return cancel, done
}

func waitForCondition(t *testing.T, timeout time.Duration, condition func() bool, errMessage string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal(errMessage)
}

func withKeepAliveTimerLock(f func()) {
	keepAliveTimerMutex.Lock()
	defer keepAliveTimerMutex.Unlock()
	f()
}

func TestNfRegistrationService_WhenEmptyConfig_ThenDeregisterNFAndStopTimer(t *testing.T) {
	testCases := []struct {
		name                         string
		sendDeregisterNFInstanceMock func(called chan<- struct{}) func() error
	}{
		{
			name: "Success",
			sendDeregisterNFInstanceMock: func(called chan<- struct{}) func() error {
				return func() error {
					select {
					case called <- struct{}{}:
					default:
					}
					return nil
				}
			},
		},
		{
			name: "ErrorInDeregisterNFInstance",
			sendDeregisterNFInstanceMock: func(called chan<- struct{}) func() error {
				return func() error {
					select {
					case called <- struct{}{}:
					default:
					}
					return errors.New("mock error")
				}
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			withKeepAliveTimerLock(func() {
				stopKeepAliveTimer()
				keepAliveTimer = time.NewTimer(60 * time.Second)
			})

			registerCalled := make(chan struct{}, 1)
			deregisterCalled := make(chan struct{}, 1)
			originalDeregisterNF := consumer.SendDeregisterNFInstance
			originalRegisterNF := registerNF

			ch := make(chan consumer.NfProfileDynamicConfig, 1)
			cancel, done := startRegistrationServiceForTest(t, ch)
			defer func() {
				cancel()
				<-done
				consumer.SendDeregisterNFInstance = originalDeregisterNF
				registerNF = originalRegisterNF
				withKeepAliveTimerLock(func() {
					stopKeepAliveTimer()
				})
			}()

			consumer.SendDeregisterNFInstance = tc.sendDeregisterNFInstanceMock(deregisterCalled)
			registerNF = func(registerCtx context.Context, newNfProfileConfig consumer.NfProfileDynamicConfig) {
				select {
				case registerCalled <- struct{}{}:
				default:
				}
			}

			ch <- consumer.NfProfileDynamicConfig{}

			select {
			case <-deregisterCalled:
			case <-time.After(500 * time.Millisecond):
				t.Fatal("expected SendDeregisterNFInstance to be called")
			}

			waitForCondition(t, 500*time.Millisecond, func() bool {
				isNil := false
				withKeepAliveTimerLock(func() {
					isNil = keepAliveTimer == nil
				})
				return isNil
			}, "expected keepAliveTimer to be nil after stopKeepAliveTimer")

			select {
			case <-registerCalled:
				t.Errorf("expected registerNF not to be called")
			default:
			}
		})
	}
}

func TestNfRegistrationService_WhenConfigChanged_ThenRegisterNFSuccessAndStartTimer(t *testing.T) {
	withKeepAliveTimerLock(func() {
		stopKeepAliveTimer()
	})
	originalSendRegisterNFInstance := consumer.SendRegisterNFInstance
	originalDiscoverUdr := consumer.DiscoverUdr
	ch := make(chan consumer.NfProfileDynamicConfig, 1)
	cancel, done := startRegistrationServiceForTest(t, ch)
	defer func() {
		cancel()
		<-done
		consumer.SendRegisterNFInstance = originalSendRegisterNFInstance
		consumer.DiscoverUdr = originalDiscoverUdr
		withKeepAliveTimerLock(func() {
			stopKeepAliveTimer()
		})
	}()

	registrationMu := sync.Mutex{}
	registrations := []consumer.NfProfileDynamicConfig{}
	registerCalled := make(chan struct{}, 1)
	discoverCalled := make(chan struct{}, 1)
	consumer.SendRegisterNFInstance = func(nfProfileDynamicConfig consumer.NfProfileDynamicConfig) (*models.NFProfile, string, error) {
		profile := &models.NFProfile{HeartBeatTimer: openapi.PtrInt32(60)}
		registrationMu.Lock()
		registrations = append(registrations, nfProfileDynamicConfig)
		registrationMu.Unlock()
		select {
		case registerCalled <- struct{}{}:
		default:
		}
		return profile, "", nil
	}
	consumer.DiscoverUdr = func() {
		select {
		case discoverCalled <- struct{}{}:
		default:
		}
	}

	newConfig := consumer.NfProfileDynamicConfig{
		Plmns: map[models.PlmnId]struct{}{
			{Mcc: "208", Mnc: "93"}: {},
		},
		Dnns: make(map[string]struct{}),
	}
	ch <- newConfig

	select {
	case <-registerCalled:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("expected SendRegisterNFInstance to be called")
	}

	select {
	case <-discoverCalled:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("expected DiscoverUdr to be called")
	}

	waitForCondition(t, 500*time.Millisecond, func() bool {
		isSet := false
		withKeepAliveTimerLock(func() {
			isSet = keepAliveTimer != nil
		})
		return isSet
	}, "expected keepAliveTimer to be initialized by startKeepAliveTimer")

	registrationMu.Lock()
	registered := append([]consumer.NfProfileDynamicConfig(nil), registrations...)
	registrationMu.Unlock()
	if len(registered) != 1 {
		t.Errorf("expected PCF to register to the NRF once, but it was called %d", len(registered))
	}
	if len(registered) > 0 && !reflect.DeepEqual(registered[0], newConfig) {
		t.Errorf("expected %+v config, received %+v", newConfig, registered)
	}
}

func TestNfRegistrationService_WhenEmptyConfig_ThenContinuesListeningForUpdates(t *testing.T) {
	originalDeregisterNF := consumer.SendDeregisterNFInstance
	originalRegisterNF := registerNF
	originalDiscoverUdr := consumer.DiscoverUdr
	ch := make(chan consumer.NfProfileDynamicConfig, 2)
	cancel, done := startRegistrationServiceForTest(t, ch)
	defer func() {
		cancel()
		<-done
		consumer.SendDeregisterNFInstance = originalDeregisterNF
		registerNF = originalRegisterNF
		consumer.DiscoverUdr = originalDiscoverUdr
		withKeepAliveTimerLock(func() {
			stopKeepAliveTimer()
		})
	}()

	withKeepAliveTimerLock(func() {
		stopKeepAliveTimer()
	})
	var deregisterCalls atomic.Int32
	consumer.SendDeregisterNFInstance = func() error {
		deregisterCalls.Add(1)
		return nil
	}
	consumer.DiscoverUdr = func() {}

	registered := make(chan consumer.NfProfileDynamicConfig, 1)
	registerNF = func(registerCtx context.Context, newNfProfileConfig consumer.NfProfileDynamicConfig) {
		registered <- newNfProfileConfig
	}

	ch <- consumer.NfProfileDynamicConfig{}
	ch <- consumer.NfProfileDynamicConfig{
		Plmns: map[models.PlmnId]struct{}{{Mcc: "001", Mnc: "01"}: {}},
		Dnns:  map[string]struct{}{},
	}

	select {
	case got := <-registered:
		if len(got.Plmns) != 1 {
			t.Fatalf("expected one PLMN in follow-up registration, got %+v", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("expected registration service to continue after empty config")
	}

	if deregisterCalls.Load() != 1 {
		t.Fatalf("expected one deregistration call, got %d", deregisterCalls.Load())
	}
}

func TestNfRegistrationService_WhenConfigChannelClosed_ThenStopsService(t *testing.T) {
	withKeepAliveTimerLock(func() {
		stopKeepAliveTimer()
		keepAliveTimer = time.NewTimer(60 * time.Second)
	})
	originalRegisterNF := registerNF
	ch := make(chan consumer.NfProfileDynamicConfig)
	cancel, done := startRegistrationServiceForTest(t, ch)
	defer func() {
		cancel()
		<-done
		registerNF = originalRegisterNF
		withKeepAliveTimerLock(func() {
			stopKeepAliveTimer()
		})
	}()

	registerCalled := make(chan struct{}, 1)
	registerNF = func(registerCtx context.Context, newNfProfileConfig consumer.NfProfileDynamicConfig) {
		select {
		case registerCalled <- struct{}{}:
		default:
		}
	}

	close(ch)

	select {
	case <-registerCalled:
		t.Fatal("expected registerNF not to be called after channel close")
	default:
	}

	waitForCondition(t, 500*time.Millisecond, func() bool {
		isNil := false
		withKeepAliveTimerLock(func() {
			isNil = keepAliveTimer == nil
		})
		return isNil
	}, "expected keepAliveTimer to be cleared after channel close")
}

func TestNfRegistrationService_ConfigChanged_RetryIfRegisterNFFails(t *testing.T) {
	originalSendRegisterNFInstance := consumer.SendRegisterNFInstance
	originalDiscoverUdr := consumer.DiscoverUdr
	ch := make(chan consumer.NfProfileDynamicConfig, 1)
	cancel, done := startRegistrationServiceForTest(t, ch)
	defer func() {
		cancel()
		<-done
		consumer.SendRegisterNFInstance = originalSendRegisterNFInstance
		consumer.DiscoverUdr = originalDiscoverUdr
		withKeepAliveTimerLock(func() {
			stopKeepAliveTimer()
		})
	}()

	var called atomic.Int32
	consumer.SendRegisterNFInstance = func(nfProfileDynamicConfig consumer.NfProfileDynamicConfig) (*models.NFProfile, string, error) {
		profile := &models.NFProfile{HeartBeatTimer: openapi.PtrInt32(60)}
		called.Add(1)
		return profile, "", errors.New("mock error")
	}
	consumer.DiscoverUdr = func() {}

	ch <- consumer.NfProfileDynamicConfig{
		Plmns: map[models.PlmnId]struct{}{
			{Mcc: "208", Mnc: "93"}: {},
		},
		Dnns: make(map[string]struct{}),
	}

	waitForCondition(t, retryTime+3*time.Second, func() bool {
		return called.Load() >= 2
	}, "expected to retry register to NRF")

	if called.Load() < 2 {
		t.Error("expected to retry register to NRF")
	}
	t.Logf("Tried %v times", called.Load())
}

func TestNfRegistrationService_WhenConfigChanged_ThenPreviousRegistrationIsCancelled(t *testing.T) {
	originalRegisterNf := registerNF
	originalDiscoverUdr := consumer.DiscoverUdr
	ch := make(chan consumer.NfProfileDynamicConfig, 1)
	cancel, done := startRegistrationServiceForTest(t, ch)
	defer func() {
		cancel()
		<-done
		registerNF = originalRegisterNf
		consumer.DiscoverUdr = originalDiscoverUdr
		withKeepAliveTimerLock(func() {
			stopKeepAliveTimer()
		})
	}()

	type registrationCall struct {
		ctx    context.Context
		config consumer.NfProfileDynamicConfig
	}
	registrations := make(chan registrationCall, 2)
	registerNF = func(registerCtx context.Context, newNfProfileConfig consumer.NfProfileDynamicConfig) {
		registrations <- registrationCall{ctx: registerCtx, config: newNfProfileConfig}
		<-registerCtx.Done() // Wait until registration is cancelled
	}
	consumer.DiscoverUdr = func() {}

	firstConfig := consumer.NfProfileDynamicConfig{
		Plmns: map[models.PlmnId]struct{}{
			{Mcc: "001", Mnc: "01"}: {},
		},
		Dnns: make(map[string]struct{}),
	}
	ch <- firstConfig

	var firstRegistration registrationCall
	select {
	case firstRegistration = <-registrations:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("expected one registration to the NRF")
	}

	secondConfig := consumer.NfProfileDynamicConfig{
		Plmns: map[models.PlmnId]struct{}{
			{Mcc: "002", Mnc: "02"}: {},
		},
		Dnns: make(map[string]struct{}),
	}
	ch <- secondConfig
	var secondRegistration registrationCall
	select {
	case secondRegistration = <-registrations:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("expected 2 registrations to the NRF")
	}

	select {
	case <-firstRegistration.ctx.Done():
		// expected
	case <-time.After(500 * time.Millisecond):
		t.Error("expected first registration context to be cancelled")
	}

	select {
	case <-secondRegistration.ctx.Done():
		t.Error("second registration context should not be cancelled")
	default:
		// expected
	}

	if !reflect.DeepEqual(firstRegistration.config, firstConfig) {
		t.Errorf("expected %+v config, received %+v", firstConfig, firstRegistration.config)
	}
	if !reflect.DeepEqual(secondRegistration.config, secondConfig) {
		t.Errorf("expected %+v config, received %+v", secondConfig, secondRegistration.config)
	}
}

func TestHeartbeatNF_Success(t *testing.T) {
	withKeepAliveTimerLock(func() {
		stopKeepAliveTimer()
		keepAliveTimer = time.NewTimer(60 * time.Second)
	})
	calledRegister := false
	originalSendRegisterNFInstance := consumer.SendRegisterNFInstance
	originalSendUpdateNFInstance := consumer.SendUpdateNFInstance
	defer func() {
		consumer.SendRegisterNFInstance = originalSendRegisterNFInstance
		consumer.SendUpdateNFInstance = originalSendUpdateNFInstance
		withKeepAliveTimerLock(func() {
			stopKeepAliveTimer()
		})
	}()

	consumer.SendUpdateNFInstance = func(patchItem []models.PatchItem) (*models.NFProfile, *models.ProblemDetails, error) {
		return &models.NFProfile{}, nil, nil
	}
	consumer.SendRegisterNFInstance = func(nfProfileDynamicConfig consumer.NfProfileDynamicConfig) (*models.NFProfile, string, error) {
		calledRegister = true
		profile := &models.NFProfile{HeartBeatTimer: openapi.PtrInt32(60)}
		return profile, "", nil
	}
	nfProfileConfig := consumer.NfProfileDynamicConfig{}
	heartbeatNF(nfProfileConfig)

	if calledRegister {
		t.Errorf("expected registerNF to be called on error")
	}
	keepAliveTimerStarted := false
	withKeepAliveTimerLock(func() {
		keepAliveTimerStarted = keepAliveTimer != nil
	})
	if !keepAliveTimerStarted {
		t.Error("expected keepAliveTimer to be initialized by startKeepAliveTimer")
	}
}

func TestHeartbeatNF_WhenNfUpdateFails_ThenNfRegistersIsCalled(t *testing.T) {
	withKeepAliveTimerLock(func() {
		stopKeepAliveTimer()
		keepAliveTimer = time.NewTimer(60 * time.Second)
	})
	calledRegister := false
	originalSendRegisterNFInstance := consumer.SendRegisterNFInstance
	originalSendUpdateNFInstance := consumer.SendUpdateNFInstance
	defer func() {
		consumer.SendRegisterNFInstance = originalSendRegisterNFInstance
		consumer.SendUpdateNFInstance = originalSendUpdateNFInstance
		withKeepAliveTimerLock(func() {
			stopKeepAliveTimer()
		})
	}()

	consumer.SendUpdateNFInstance = func(patchItem []models.PatchItem) (*models.NFProfile, *models.ProblemDetails, error) {
		return &models.NFProfile{}, nil, errors.New("mock error")
	}

	consumer.SendRegisterNFInstance = func(nfProfileDynamicConfig consumer.NfProfileDynamicConfig) (*models.NFProfile, string, error) {
		profile := &models.NFProfile{HeartBeatTimer: openapi.PtrInt32(60)}
		calledRegister = true
		return profile, "", nil
	}

	nfProfileConfig := consumer.NfProfileDynamicConfig{}
	heartbeatNF(nfProfileConfig)

	if !calledRegister {
		t.Errorf("expected registerNF to be called on error")
	}
	keepAliveTimerStarted := false
	withKeepAliveTimerLock(func() {
		keepAliveTimerStarted = keepAliveTimer != nil
	})
	if !keepAliveTimerStarted {
		t.Error("expected keepAliveTimer to be initialized by startKeepAliveTimer")
	}
}

func TestStartKeepAliveTimer_UsesProfileTimerOnlyWhenGreaterThanZero(t *testing.T) {
	testCases := []struct {
		name             string
		profileTime      int32
		expectedDuration time.Duration
	}{
		{
			name:             "Profile heartbeat time is zero, use default time",
			profileTime:      0,
			expectedDuration: 60 * time.Second,
		},
		{
			name:             "Profile heartbeat time is smaller than zero, use default time",
			profileTime:      -5,
			expectedDuration: 60 * time.Second,
		},
		{
			name:             "Profile heartbeat time is greater than zero, use profile time",
			profileTime:      15,
			expectedDuration: 15 * time.Second,
		},
		{
			name:             "Profile heartbeat time is greater than default time, use profile time",
			profileTime:      90,
			expectedDuration: 90 * time.Second,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			withKeepAliveTimerLock(func() {
				stopKeepAliveTimer()
				keepAliveTimer = time.NewTimer(25 * time.Second)
			})
			defer func() {
				withKeepAliveTimerLock(func() {
					stopKeepAliveTimer()
				})
			}()
			var capturedDuration time.Duration

			afterFunc = func(d time.Duration, _ func()) *time.Timer {
				capturedDuration = d
				return time.NewTimer(25 * time.Second)
			}
			defer func() { afterFunc = time.AfterFunc }()

			startKeepAliveTimer(tc.profileTime, consumer.NfProfileDynamicConfig{})
			if tc.expectedDuration != capturedDuration {
				t.Errorf("Expected %v duration, got %v", tc.expectedDuration, capturedDuration)
			}
		})
	}
}
