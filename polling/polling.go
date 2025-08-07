// SPDX-FileCopyrightText: 2025 Canonical Ltd

// SPDX-License-Identifier: Apache-2.0
//

package polling

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"time"

	"github.com/omec-project/openapi/models"
	"github.com/omec-project/openapi/nfConfigApi"
	"github.com/omec-project/pcf/consumer"
	"github.com/omec-project/pcf/logger"
)

const (
	initialPollingInterval = 5 * time.Second
	pollingMaxBackoff      = 40 * time.Second
	pollingBackoffFactor   = 2
	pollingPath            = "/nfconfig/policy-control"
)

type nfConfigPoller struct {
	nfProfileConfigChan    chan<- consumer.NfProfileDynamicConfig
	currentPolicyControl   []nfConfigApi.PolicyControl
	currentNfProfileConfig consumer.NfProfileDynamicConfig
	client                 *http.Client
}

// StartPollingService initializes the polling service and starts it. The polling service
// continuously makes a HTTP GET request to the webconsole and updates the network configuration
func StartPollingService(ctx context.Context, webuiUri string, nfProfileConfigChan chan<- consumer.NfProfileDynamicConfig) {
	poller := nfConfigPoller{
		nfProfileConfigChan:    nfProfileConfigChan,
		currentPolicyControl:   []nfConfigApi.PolicyControl{},
		currentNfProfileConfig: consumer.NfProfileDynamicConfig{},
		client:                 &http.Client{Timeout: initialPollingInterval},
	}
	pccPolicies = make(map[models.Snssai]*PccPolicy)
	interval := initialPollingInterval
	pollingEndpoint := webuiUri + pollingPath
	logger.PollConfigLog.Infof("Started polling service on %s every %v", pollingEndpoint, initialPollingInterval)
	for {
		select {
		case <-ctx.Done():
			logger.PollConfigLog.Infoln("Polling service shutting down")
			return
		case <-time.After(interval):
			newConfig, err := fetchPolicyControlConfig(&poller, pollingEndpoint)
			if err != nil {
				interval = minDuration(interval*time.Duration(pollingBackoffFactor), pollingMaxBackoff)
				logger.PollConfigLog.Errorf("Polling error. Retrying in %v: %+v", interval, err)
				continue
			}
			interval = initialPollingInterval
			poller.handlePolledPolicyControl(newConfig)
		}
	}
}

var fetchPolicyControlConfig = func(p *nfConfigPoller, endpoint string) ([]nfConfigApi.PolicyControl, error) {
	return p.fetchPolicyControlConfig(endpoint)
}

func (p *nfConfigPoller) fetchPolicyControlConfig(pollingEndpoint string) ([]nfConfigApi.PolicyControl, error) {
	ctx, cancel := context.WithTimeout(context.Background(), initialPollingInterval)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pollingEndpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP GET %v failed: %w", pollingEndpoint, err)
	}
	defer resp.Body.Close()

	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "application/json") {
		return nil, fmt.Errorf("unexpected Content-Type: got %s, want application/json", contentType)
	}

	switch resp.StatusCode {
	case http.StatusOK:
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read response body: %w", err)
		}

		var config []nfConfigApi.PolicyControl
		if err := json.Unmarshal(body, &config); err != nil {
			return nil, fmt.Errorf("failed to parse JSON response: %w", err)
		}
		return config, nil

	case http.StatusBadRequest, http.StatusInternalServerError:
		return nil, fmt.Errorf("server returned %d error code", resp.StatusCode)
	default:
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
}

func (p *nfConfigPoller) handlePolledPolicyControl(newPolicyControlConfig []nfConfigApi.PolicyControl) {
	if reflect.DeepEqual(p.currentPolicyControl, newPolicyControlConfig) {
		logger.PollConfigLog.Debugf("Policy control config did not change %+v", p.currentPolicyControl)
		return
	}
	newNfProfileDynamicConfig := extractNfProfileDynamicConfig(newPolicyControlConfig)
	if !reflect.DeepEqual(p.currentNfProfileConfig, newNfProfileDynamicConfig) {
		logger.PollConfigLog.Debugf("NF profile config changed %+v. Updating NF registration", newNfProfileDynamicConfig)
		p.currentNfProfileConfig = newNfProfileDynamicConfig
		p.nfProfileConfigChan <- p.currentNfProfileConfig
	}
	if havePccRulesChanged(p.currentPolicyControl, newPolicyControlConfig) {
		updatePccPolicy(newPolicyControlConfig)
	}
	p.currentPolicyControl = newPolicyControlConfig
	logger.PollConfigLog.Infof("Policy control config changed. New Policy control config: %+v", p.currentPolicyControl)
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

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
