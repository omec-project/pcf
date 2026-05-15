// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0
//

package notifyevent

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/pcf/logger"
)

const SendSMpolicyUpdateNotifyEventName = "SendSMpolicyUpdateNotify"

const sendSMPolicyUpdateNotifyTimeout = 10 * time.Second

var sendSMPolicyUpdateNotifyHTTPClient = &http.Client{Timeout: sendSMPolicyUpdateNotifyTimeout}

type SendSMpolicyUpdateNotifyEvent struct {
	request *models.SmPolicyNotification
	uri     string
}

// Handle processes the SM policy update notification event
func (e SendSMpolicyUpdateNotifyEvent) Handle() {
	logger.NotifyEventLog.Infoln("handle SendSMpolicyUpdateNotifyEvent")
	if e.uri == "" {
		logger.NotifyEventLog.Warnln("SM Policy Update Notification Error [URI is empty]")
		return
	}
	if e.request == nil {
		logger.NotifyEventLog.Warnln("SM Policy Update Notification Error [request is nil]")
		return
	}
	payload, err := json.Marshal(e.request)
	if err != nil {
		logger.NotifyEventLog.Warnf("SM Policy Update Notification Failed to marshal request[%s]", err.Error())
		return
	}
	requestCtx, cancel := context.WithTimeout(context.Background(), sendSMPolicyUpdateNotifyTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(requestCtx, http.MethodPost, e.uri, bytes.NewReader(payload))
	if err != nil {
		logger.NotifyEventLog.Warnf("SM Policy Update Notification Failed to build request[%s]", err.Error())
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	logger.NotifyEventLog.Infoln("send SM Policy Update Notification to SMF")
	httpResponse, err := sendSMPolicyUpdateNotifyHTTPClient.Do(req)
	if err != nil {
		if httpResponse != nil {
			logger.NotifyEventLog.Warnf("SM Policy Update Notification Error[%s]", httpResponse.Status)
		} else {
			logger.NotifyEventLog.Warnf("SM Policy Update Notification Failed[%s]", err.Error())
		}
		return
	} else if httpResponse == nil {
		logger.NotifyEventLog.Warnln("SM Policy Update Notification Failed [HTTP Response is nil]")
		return
	}
	defer func() {
		if resCloseErr := httpResponse.Body.Close(); resCloseErr != nil {
			logger.NotifyEventLog.Errorf("SM Policy Update Notification response body cannot close: %+v", resCloseErr)
		}
	}()
	if httpResponse.StatusCode != http.StatusOK && httpResponse.StatusCode != http.StatusNoContent {
		logger.NotifyEventLog.Warnln("SM Policy Update Notification Failed")
	} else {
		logger.NotifyEventLog.Debugln("SM Policy Update Notification Success")
	}
}
