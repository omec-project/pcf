// Copyright (C) 2024-Present Intel Corporation
// SPDX-FileCopyrightText: 2025 Canonical Ltd
// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0
//

// Package nfregistration adapts the PCF to the shared NRF registration service.
package nfregistration

import (
	"context"
	"time"

	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/openapi/v2/nrfregistration"
	"github.com/omec-project/pcf/consumer"
	"github.com/omec-project/pcf/logger"
)

var service = newService()

func newService() *nrfregistration.Service[consumer.NfProfileDynamicConfig] {
	// The consumer functions are looked up on every call so tests can replace them.
	svc, err := nrfregistration.New(nrfregistration.Config[consumer.NfProfileDynamicConfig]{
		NfName:  "PCF",
		Log:     logger.NrfRegistrationLog,
		IsEmpty: func(cfg consumer.NfProfileDynamicConfig) bool { return len(cfg.Plmns) == 0 },
		Register: func(ctx context.Context, cfg consumer.NfProfileDynamicConfig) (*models.NFProfile, error) {
			nfProfile, _, err := consumer.SendRegisterNFInstance(ctx, cfg)
			return nfProfile, err
		},
		Update: func(ctx context.Context, patch []models.PatchItem) (*models.NFProfile, *models.ProblemDetails, error) {
			return consumer.SendUpdateNFInstance(ctx, patch)
		},
		Deregister: func(ctx context.Context) error { return consumer.SendDeregisterNFInstance(ctx) },
		// The PCF refreshes its default UDR URI whenever a non-empty config is accepted.
		OnConfig: func(consumer.NfProfileDynamicConfig) { consumer.DiscoverUdr() },
	})
	if err != nil {
		panic(err) // the config above is static, so this is a programming error
	}
	return svc
}

// StartNfRegistrationService starts the registration service. If the new config is empty, the NF
// deregisters from the NRF. Else, it registers to the NRF. It cancels the registration in progress
// so that only one registration process runs at the time.
func StartNfRegistrationService(ctx context.Context, nfProfileConfigChan <-chan consumer.NfProfileDynamicConfig) {
	service.Start(ctx, nfProfileConfigChan)
}

// deregisterTimeout bounds DeregisterNF: it waits for the registration work in progress, which it cancels, and
// then sends the DELETE, and an NRF that does not answer must not hold up the termination of the NF.
var deregisterTimeout = 10 * time.Second

// DeregisterNF stops the heartbeat and deregisters the NF from the NRF.
var DeregisterNF = func() {
	ctx, cancel := context.WithTimeout(context.Background(), deregisterTimeout)
	defer cancel()
	service.Deregister(ctx)
}
