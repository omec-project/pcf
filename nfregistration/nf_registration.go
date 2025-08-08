// SPDX-FileCopyrightText: 2025 Canonical Ltd
// SPDX-FileCopyrightText: 2024 Intel Corporation
// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0
//

package nfregistration

import (
	"context"
	"sync"
	"time"

	"github.com/omec-project/openapi/models"
	"github.com/omec-project/pcf/consumer"
	"github.com/omec-project/pcf/logger"
)

var (
	keepAliveTimer      *time.Timer
	keepAliveTimerMutex sync.Mutex
	registerCtxMutex    sync.Mutex
	afterFunc           = time.AfterFunc
)

const (
	defaultHeartbeatTimer int32 = 60
	retryTime                   = 10 * time.Second
)

// StartNfRegistrationService starts the registration service. If the new config is empty, the NF
// deregisters from the NRF. Else, it registers to the NRF. It cancels registerCancel to ensure
// that only one registration process runs at the time.
func StartNfRegistrationService(ctx context.Context, nfProfileConfigChan <-chan consumer.NfProfileDynamicConfig) {
	var registerCancel context.CancelFunc
	var registerCtx context.Context
	logger.NrfRegistrationLog.Infoln("started NF registration to NRF service")
	for {
		select {
		case <-ctx.Done():
			if registerCancel != nil {
				registerCancel()
			}
			logger.NrfRegistrationLog.Infoln("NF registration service shutting down")
			return
		case newNfProfileConfig := <-nfProfileConfigChan:
			// Cancel current sync if running
			if registerCancel != nil {
				logger.NrfRegistrationLog.Infoln("NF registration context cancelled")
				registerCancel()
			}

			if len(newNfProfileConfig.Plmns) == 0 {
				logger.NrfRegistrationLog.Debugln("NF profile config is empty. PCF will deregister")
				DeregisterNF()
			} else {
				logger.NrfRegistrationLog.Debugln("NF profile config is not empty. PCF will update registration")
				registerCtx, registerCancel = context.WithCancel(context.Background())
				// Create new cancellable context for this registration
				go registerNF(registerCtx, newNfProfileConfig)
				consumer.DiscoverUdr()
			}
		}
	}
}

// registerNF sends a RegisterNFInstance. If it fails, it keeps retrying, until the context is cancelled by StartNfRegistrationService
var registerNF = func(registerCtx context.Context, newNfProfileConfig consumer.NfProfileDynamicConfig) {
	registerCtxMutex.Lock()
	defer registerCtxMutex.Unlock()
	interval := 0 * time.Millisecond
	for {
		select {
		case <-registerCtx.Done():
			logger.NrfRegistrationLog.Infoln("no-op. Registration context was cancelled")
			return
		case <-time.After(interval):
			nfProfile, _, err := consumer.SendRegisterNFInstance(newNfProfileConfig)
			if err != nil {
				logger.NrfRegistrationLog.Errorln("register PCF instance to NRF failed. Will retry.", err.Error())
				interval = retryTime
				continue
			}
			logger.NrfRegistrationLog.Infoln("register PCF instance to NRF with updated profile succeeded")
			startKeepAliveTimer(nfProfile.HeartBeatTimer, newNfProfileConfig)
			return
		}
	}
}

// heartbeatNF is the callback function, this is called when keepalivetimer elapsed.
// It sends a Update NF instance to the NRF. If it fails, it tries to register again.
// keepAliveTimer is restarted at the end.
func heartbeatNF(nfProfileConfig consumer.NfProfileDynamicConfig) {
	keepAliveTimerMutex.Lock()
	if keepAliveTimer == nil {
		keepAliveTimerMutex.Unlock()
		logger.NrfRegistrationLog.Infoln("heartbeat timer has been stopped, heartbeat will not be sent to NRF")
		return
	}
	keepAliveTimerMutex.Unlock()

	patchItem := []models.PatchItem{
		{
			Op:    "replace",
			Path:  "/nfStatus",
			Value: "REGISTERED",
		},
	}
	nfProfile, problemDetails, err := consumer.SendUpdateNFInstance(patchItem)

	if shouldRegister(problemDetails, err) {
		logger.NrfRegistrationLog.Debugln("NF heartbeat failed. Trying to register again")
		nfProfile, _, err = consumer.SendRegisterNFInstance(nfProfileConfig)
		if err != nil {
			logger.NrfRegistrationLog.Errorln("register PCF instance error:", err.Error())
		} else {
			logger.NrfRegistrationLog.Infoln("register PCF instance to NRF with updated profile succeeded")
		}
	} else {
		logger.NrfRegistrationLog.Debugln("PCF update NF instance (heartbeat) succeeded")
	}
	startKeepAliveTimer(nfProfile.HeartBeatTimer, nfProfileConfig)
}

func shouldRegister(problemDetails *models.ProblemDetails, err error) bool {
	if problemDetails != nil {
		logger.NrfRegistrationLog.Warnln("PCF update NF instance (heartbeat) problem details:", problemDetails)
		return true
	}
	if err != nil {
		logger.NrfRegistrationLog.Warnln("PCF update NF instance (heartbeat) error:", err.Error())
		return true
	}
	return false
}

var DeregisterNF = func() {
	keepAliveTimerMutex.Lock()
	stopKeepAliveTimer()
	keepAliveTimerMutex.Unlock()
	err := consumer.SendDeregisterNFInstance()
	if err != nil {
		logger.NrfRegistrationLog.Warnln("deregister instance from NRF error:", err.Error())
		return
	}
	logger.NrfRegistrationLog.Infoln("deregister instance from NRF successful")
}

func startKeepAliveTimer(profileHeartbeatTimer int32, nfProfileConfig consumer.NfProfileDynamicConfig) {
	keepAliveTimerMutex.Lock()
	defer keepAliveTimerMutex.Unlock()
	stopKeepAliveTimer()
	heartbeatTimer := defaultHeartbeatTimer
	if profileHeartbeatTimer > 0 {
		heartbeatTimer = profileHeartbeatTimer
	}
	heartbeatFunction := func() { heartbeatNF(nfProfileConfig) }
	// AfterFunc starts timer and waits for keepAliveTimer to elapse and then calls heartbeatNF function
	keepAliveTimer = afterFunc(time.Duration(heartbeatTimer)*time.Second, heartbeatFunction)
	logger.NrfRegistrationLog.Debugf("started heartbeat timer: %v sec", heartbeatTimer)
}

func stopKeepAliveTimer() {
	if keepAliveTimer != nil {
		keepAliveTimer.Stop()
		keepAliveTimer = nil
		logger.NrfRegistrationLog.Debugln("stopped heartbeat timer")
	}
}
