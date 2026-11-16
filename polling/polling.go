// Copyright (C) 2026 Intel Corporation
// SPDX-FileCopyrightText: 2025 Canonical Ltd
// SPDX-License-Identifier: Apache-2.0

package polling

import (
	"context"
	"reflect"
	"time"

	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/openapi/v2/nfConfigApi"
	"github.com/omec-project/openapi/v2/nfconfigpoll"
	"github.com/omec-project/pcf/consumer"
	"github.com/omec-project/pcf/logger"
)

const (
	initialPollingInterval = 5 * time.Second
	pollingPath            = "/nfconfig/policy-control"
)

// nfConfigPoller holds the PCF specific state of the policy control handling. The polling loop,
// fetching and the dedupe of the whole policy list are done by nfconfigpoll.
type nfConfigPoller struct {
	nfProfileConfigChan    chan<- consumer.NfProfileDynamicConfig
	currentPolicyControl   []nfConfigApi.PolicyControl
	currentNfProfileConfig consumer.NfProfileDynamicConfig
}

// StartPollingService initializes the polling service and starts it. The polling service
// continuously makes a HTTP GET request to the webconsole and updates the network configuration
func StartPollingService(ctx context.Context, webuiUri string, nfProfileConfigChan chan<- consumer.NfProfileDynamicConfig) {
	poller, err := newPoller(webuiUri, nfProfileConfigChan, initialPollingInterval)
	if err != nil {
		logger.PollConfigLog.Errorf("failed to start polling service: %v", err)
		return
	}
	poller.Run(ctx)
}

func newPoller(webuiUri string, nfProfileConfigChan chan<- consumer.NfProfileDynamicConfig, interval time.Duration) (*nfconfigpoll.Poller[[]nfConfigApi.PolicyControl], error) {
	handler := &nfConfigPoller{
		nfProfileConfigChan:    nfProfileConfigChan,
		currentPolicyControl:   []nfConfigApi.PolicyControl{},
		currentNfProfileConfig: consumer.NfProfileDynamicConfig{},
	}
	return nfconfigpoll.New(nfconfigpoll.Config[[]nfConfigApi.PolicyControl]{
		Name:     "policy control",
		Endpoint: webuiUri + pollingPath,
		Log:      logger.PollConfigLog,
		Interval: interval,
		Initial:  []nfConfigApi.PolicyControl{},
		OnChange: handler.handlePolledPolicyControl,
	})
}

// handlePolledPolicyControl applies a policy control config that differs from the previous one. It
// returns an error, so that the config is delivered again on the next poll, only if the NF profile
// config could not be delivered; nothing is recorded as applied in that case.
func (p *nfConfigPoller) handlePolledPolicyControl(ctx context.Context, newPolicyControlConfig []nfConfigApi.PolicyControl) error {
	newNfProfileDynamicConfig := extractNfProfileDynamicConfig(newPolicyControlConfig)
	if !reflect.DeepEqual(p.currentNfProfileConfig, newNfProfileDynamicConfig) {
		logger.PollConfigLog.Debugf("NF profile config changed %+v. Updating NF registration", newNfProfileDynamicConfig)
		if err := nfconfigpoll.Send(ctx, p.nfProfileConfigChan, newNfProfileDynamicConfig); err != nil {
			return err
		}
		p.currentNfProfileConfig = newNfProfileDynamicConfig
	}
	if havePccRulesChanged(p.currentPolicyControl, newPolicyControlConfig) {
		updatePccPolicy(newPolicyControlConfig)
		// The cache now describes the new policy, but sessions already running still hold the
		// decisions they were given. Bring them over rather than leaving the same subscriber on
		// the same slice treated differently depending on when they attached.
		notifyPolicyControlChanged()
	}
	p.currentPolicyControl = newPolicyControlConfig
	return nil
}

func extractNfProfileDynamicConfig(policyConfig []nfConfigApi.PolicyControl) consumer.NfProfileDynamicConfig {
	plmnSet := make(map[models.PlmnId]struct{})
	dnnSet := make(map[string]struct{})

	for _, policy := range policyConfig {
		plmn := models.PlmnId{
			Mcc: policy.PlmnId.Mcc,
			Mnc: policy.PlmnId.Mnc,
		}
		plmnSet[plmn] = struct{}{}

		for _, dnn := range policy.Dnns {
			dnnSet[dnn] = struct{}{}
		}
	}
	return consumer.NfProfileDynamicConfig{
		Plmns: plmnSet,
		Dnns:  dnnSet,
	}
}

func havePccRulesChanged(prev, curr []nfConfigApi.PolicyControl) bool {
	if len(prev) != len(curr) {
		return true
	}
	for i := range curr {
		if !reflect.DeepEqual(prev[i].Snssai, curr[i].Snssai) ||
			!reflect.DeepEqual(prev[i].PccRules, curr[i].PccRules) {
			return true
		}
	}
	return false
}
