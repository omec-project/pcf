// Copyright (C) 2026 Intel Corporation
// SPDX-FileCopyrightText: 2024 Canonical Ltd.
// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
// Copyright 2019 free5GC.org
// SPDX-License-Identifier: Apache-2.0

package logger

import (
	utilLogger "github.com/omec-project/util/logger"
	"go.uber.org/zap/zapcore"
)

const (
	FieldSupi string = "supi"
)

var component = utilLogger.NewComponent("PCF")

var (
	AppLog                 = component.Category("App")
	InitLog                = component.Category("Init")
	CfgLog                 = component.Category("CFG")
	HandlerLog             = component.Category("Handler")
	BdtpolicyLog           = component.Category("Bdtpolicy")
	AMpolicyLog            = component.Category("Ampolicy")
	PolicyAuthorizationLog = component.Category("PolicyAuth")
	SMpolicyLog            = component.Category("SMpolicy")
	UtilLog                = component.Category("Util")
	CallbackLog            = component.Category("Callback")
	OamLog                 = component.Category("OAM")
	CtxLog                 = component.Category("Context")
	ConsumerLog            = component.Category("Consumer")
	GinLog                 = component.Category("GIN")
	NotifyEventLog         = component.Category("NotifyEvent")
	ProducerLog            = component.Category("Producer")
	PollConfigLog          = component.Category("PollConfig")
	NrfRegistrationLog     = component.Category("NrfRegistration")
)

// SetLogLevel: set the log level (panic|fatal|error|warn|info|debug)
func SetLogLevel(level zapcore.Level) {
	InitLog.Infoln("set log level:", level)
	component.SetLevel(level)
}
