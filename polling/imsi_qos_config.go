// SPDX-FileCopyrightText: 2025 Canonical Ltd

// SPDX-License-Identifier: Apache-2.0
//

package polling

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/omec-project/openapi/models"
	"github.com/omec-project/openapi/nfConfigApi"
	"github.com/omec-project/pcf/logger"
	"github.com/omec-project/util/idgenerator"
)

const imsiQosPath = "/nfconfig/qos"

var imsiRegex = regexp.MustCompile(`^imsi-\d{15,16}$`)

var GetImsiSessionRules = func(dnn, imsi string) (map[string]*models.SessionRule, error) {
	if dnn == "" {
		return nil, fmt.Errorf("invalid DNN. DNN must not be empty string")
	}
	if !imsiRegex.MatchString(imsi) {
		return nil, fmt.Errorf("invalid IMSI format %s", imsi)
	}
	sessionPolicies := make(map[string]*models.SessionRule)
	pollingEndpoint := imsiQosPath + "/" + dnn + "/" + imsi
	imsiQos, err := fetchImsiQos(pollingEndpoint)
	if err != nil {
		return nil, fmt.Errorf("fetchImsiQos failed for %s: %w", pollingEndpoint, err)
	}
	idGenerator := idgenerator.NewGenerator(1, math.MaxInt16)
	for _, data := range imsiQos {
		id, err := idGenerator.Allocate()
		if err != nil {
			logger.PollConfigLog.Errorf("ID generator allocation failed: %v", err)
			continue
		}
		key := dnn + "-" + strconv.Itoa(int(id))
		sessionPolicies[key] = makeSessionRule(key, data)
	}
	return sessionPolicies, nil
}

var fetchImsiQos = func(pollingEndpoint string) ([]nfConfigApi.ImsiQos, error) {
	ctx, cancel := context.WithTimeout(context.Background(), initialPollingInterval)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pollingEndpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: initialPollingInterval}
	resp, err := client.Do(req)
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

		var config []nfConfigApi.ImsiQos
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

func makeSessionRule(id string, dnnQoS nfConfigApi.ImsiQos) *models.SessionRule {
	return &models.SessionRule{
		SessRuleId: id,
		AuthDefQos: &models.AuthorizedDefaultQos{
			Var5qi: dnnQoS.FiveQi,
			Arp:    &models.Arp{PriorityLevel: dnnQoS.ArpPriorityLevel},
		},
		AuthSessAmbr: &models.Ambr{
			Uplink:   dnnQoS.MbrUplink,
			Downlink: dnnQoS.MbrDownlink,
		},
	}
}
