// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0
//

package notifyevent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
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

// Handle processes the SM policy update notification event.
func (e SendSMpolicyUpdateNotifyEvent) Handle() {
	logger.NotifyEventLog.Infoln("handle SendSMpolicyUpdateNotifyEvent")
	if err := SendSMPolicyUpdateNotification(e.uri, e.request); err != nil {
		logger.NotifyEventLog.Warnf("SM Policy Update Notification Failed: %s", err.Error())
		return
	}
	logger.NotifyEventLog.Debugln("SM Policy Update Notification Success")
}

// smPolicyUpdateNotificationPath is appended to the SMF's notification URI when it is not there
// already.
//
// TS 29.512 defines the callback as {notificationUri}/update -- the SMF supplies the base resource
// at policy-create time and advertises it without the suffix, so posting the base returns 404.
//
// The suffix is added here **only when absent**, because this sender has two kinds of caller.
// The application-function paths reach it through DispatchSendSMPolicyUpdateNotifyEvent, which
// has always appended the suffix itself; appending again produced /update/update and a 404 that
// looked exactly like the one this is meant to prevent. The polled trigger calls this sender
// directly and has no dispatcher to do it.
const smPolicyUpdateNotificationPath = "/update"

// SendSMPolicyUpdateNotification posts the notification and reports what happened.
//
// The event handler above discards the result, which is right for a caller that has nothing to do
// with a failure. A caller that decides what to record next needs to know: a notification the SMF
// never received must not be treated as delivered, or the sender's idea of what the SMF knows
// drifts from the truth with nothing to correct it.
func SendSMPolicyUpdateNotification(uri string, request *models.SmPolicyNotification) error {
	if uri == "" {
		return errors.New("URI is empty")
	}
	if request == nil {
		return errors.New("request is nil")
	}
	payload, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("marshalling the request: %w", err)
	}

	uri = strings.TrimSuffix(uri, "/")
	if !strings.HasSuffix(uri, smPolicyUpdateNotificationPath) {
		uri += smPolicyUpdateNotificationPath
	}

	requestCtx, cancel := context.WithTimeout(context.Background(), sendSMPolicyUpdateNotifyTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(requestCtx, http.MethodPost, uri, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("building the request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	logger.NotifyEventLog.Infoln("send SM Policy Update Notification to SMF")
	httpResponse, err := sendSMPolicyUpdateNotifyHTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("sending to %s: %w", uri, err)
	}
	if httpResponse == nil {
		return errors.New("HTTP response is nil")
	}
	defer func() {
		if resCloseErr := httpResponse.Body.Close(); resCloseErr != nil {
			logger.NotifyEventLog.Errorf("SM Policy Update Notification response body cannot close: %+v", resCloseErr)
		}
	}()

	if httpResponse.StatusCode != http.StatusOK && httpResponse.StatusCode != http.StatusNoContent {
		return fmt.Errorf("SMF answered %s", httpResponse.Status)
	}
	return nil
}
