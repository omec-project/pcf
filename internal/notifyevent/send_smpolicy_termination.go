// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0
//

package notifyevent

import (
	"context"
	"net/http"

	"github.com/omec-project/openapi/models"
	"github.com/omec-project/pcf/logger"
	"github.com/omec-project/pcf/util"
)

const SendSMpolicyTerminationNotifyEventName = "SendSMpolicyTerminationNotify"

type SendSMpolicyTerminationNotifyEvent struct {
	request *models.TerminationNotification
	uri     string
}

// Handle processes the SM policy termination notification event
func (e SendSMpolicyTerminationNotifyEvent) Handle() {
	logger.NotifyEventLog.Infoln("handle SendSMpolicyTerminationNotifyEvent")
	if e.uri == "" {
		logger.NotifyEventLog.Warnln("SM Policy Termination Request Notification Error[URI is empty]")
		return
	}
	client := util.GetNpcfSMPolicyCallbackClient()
	logger.NotifyEventLog.Infoln("SM Policy Termination Request Notification to SMF")
	rsp, err := client.DefaultCallbackApi.SmPolicyControlTerminationRequestNotification(context.Background(), e.uri, *e.request)
	if err != nil {
		if rsp != nil {
			logger.NotifyEventLog.Warnf("SM Policy Termination Request Notification Error[%s]", rsp.Status)
		} else {
			logger.NotifyEventLog.Warnf("SM Policy Termination Request Notification Error[%s]", err.Error())
		}
		return
	} else if rsp == nil {
		logger.NotifyEventLog.Warnln("SM Policy Termination Request Notification Error[HTTP Response is nil]")
		return
	}
	defer func() {
		if resCloseErr := rsp.Body.Close(); resCloseErr != nil {
			logger.NotifyEventLog.Errorf("NFInstancesStoreApi response body cannot close: %+v", resCloseErr)
		}
	}()
	if rsp.StatusCode != http.StatusNoContent {
		logger.NotifyEventLog.Warnln("SM Policy Termination Request Notification Failed")
	} else {
		logger.NotifyEventLog.Debugln("SM Policy Termination Request Notification Success")
	}
}

// HandleEvent implements the EventHandler interface for the dispatcher
func (e SendSMpolicyTerminationNotifyEvent) HandleEvent(eventName string, data any) error {
	// This method is called by the dispatcher
	e.Handle()
	return nil
}

// NewSendSMpolicyTerminationNotifyEvent creates a new termination notification event
func NewSendSMpolicyTerminationNotifyEvent(uri string, request *models.TerminationNotification) SendSMpolicyTerminationNotifyEvent {
	return SendSMpolicyTerminationNotifyEvent{
		uri:     uri,
		request: request,
	}
}
