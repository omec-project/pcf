// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0
//

package notifyevent

import (
	"fmt"

	"github.com/omec-project/pcf/logger"
)

// NotifyListener implements the EventHandler interface
type NotifyListener struct{}

// HandleEvent processes events based on their name
func (nl NotifyListener) HandleEvent(eventName string, data any) error {
	switch eventName {
	case SendSMpolicyUpdateNotifyEventName:
		if event, ok := data.(SendSMpolicyUpdateNotifyEvent); ok {
			event.Handle()
			return nil
		}
		return fmt.Errorf("invalid data type for %s event", eventName)
	case SendSMpolicyTerminationNotifyEventName:
		if event, ok := data.(SendSMpolicyTerminationNotifyEvent); ok {
			event.Handle()
			return nil
		}
		return fmt.Errorf("invalid data type for %s event", eventName)
	default:
		logger.NotifyEventLog.Errorf("registered an invalid user event: %s", eventName)
		return fmt.Errorf("unknown event: %s", eventName)
	}
}
