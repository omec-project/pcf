// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0
//

package notifyevent

import (
	"fmt"
	"sync"

	"github.com/omec-project/openapi/models"
	"github.com/omec-project/pcf/logger"
)

// EventHandler defines the interface for handling events
type EventHandler interface {
	HandleEvent(eventName string, data any) error
}

// Dispatcher manages event handlers and dispatching
type Dispatcher struct {
	handlers map[string][]EventHandler
	mu       sync.RWMutex
}

// NewDispatcher creates a new event dispatcher
func NewDispatcher() *Dispatcher {
	return &Dispatcher{
		handlers: make(map[string][]EventHandler),
	}
}

// Register registers an event handler for specific event names
func (d *Dispatcher) Register(handler EventHandler, eventNames ...string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	for _, eventName := range eventNames {
		d.handlers[eventName] = append(d.handlers[eventName], handler)
	}
	return nil
}

// Dispatch sends an event to all registered handlers
func (d *Dispatcher) Dispatch(eventName string, data any) error {
	d.mu.RLock()
	handlers, exists := d.handlers[eventName]
	d.mu.RUnlock()

	if !exists {
		logger.NotifyEventLog.Errorf("no handlers registered for event: %s", eventName)
		return fmt.Errorf("no handlers registered for event: %s", eventName)
	}

	for _, handler := range handlers {
		if err := handler.HandleEvent(eventName, data); err != nil {
			logger.NotifyEventLog.Errorf("handler error for event %s: %v", eventName, err)
			return fmt.Errorf("handler error for event %s: %w", eventName, err)
		}
	}
	return nil
}

var notifyDispatcher *Dispatcher

func RegisterNotifyDispatcher() error {
	notifyDispatcher = NewDispatcher()
	if err := notifyDispatcher.Register(NotifyListener{},
		SendSMpolicyUpdateNotifyEventName,
		SendSMpolicyTerminationNotifyEventName); err != nil {
		return err
	}
	return nil
}

func DispatchSendSMPolicyUpdateNotifyEvent(uri string, request *models.SmPolicyNotification) {
	if notifyDispatcher == nil {
		logger.NotifyEventLog.Errorf("notifyDispatcher is nil")
		return
	}
	err := notifyDispatcher.Dispatch(SendSMpolicyUpdateNotifyEventName, SendSMpolicyUpdateNotifyEvent{
		uri:     uri,
		request: request,
	})
	if err != nil {
		logger.NotifyEventLog.Errorln(err)
	}
}

func DispatchSendSMPolicyTerminationNotifyEvent(uri string, request *models.TerminationNotification) {
	if notifyDispatcher == nil {
		logger.NotifyEventLog.Errorf("notifyDispatcher is nil")
		return
	}
	err := notifyDispatcher.Dispatch(SendSMpolicyTerminationNotifyEventName, SendSMpolicyTerminationNotifyEvent{
		uri:     uri,
		request: request,
	})
	if err != nil {
		logger.NotifyEventLog.Errorln(err)
	}
}
