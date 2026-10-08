// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
// Copyright 2019 free5GC.org
// SPDX-FileCopyrightText: 2024 Canonical Ltd.
// SPDX-License-Identifier: Apache-2.0
//

package logger

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	log                    *zap.Logger
	AppLog                 *zap.SugaredLogger
	InitLog                *zap.SugaredLogger
	CfgLog                 *zap.SugaredLogger
	HandlerLog             *zap.SugaredLogger
	BdtpolicyLog           *zap.SugaredLogger
	PolicyAuthorizationLog *zap.SugaredLogger
	AMpolicyLog            *zap.SugaredLogger
	SMpolicyLog            *zap.SugaredLogger
	UtilLog                *zap.SugaredLogger
	CallbackLog            *zap.SugaredLogger
	OamLog                 *zap.SugaredLogger
	CtxLog                 *zap.SugaredLogger
	ConsumerLog            *zap.SugaredLogger
	GinLog                 *zap.SugaredLogger
	NotifyEventLog         *zap.SugaredLogger
	ProducerLog            *zap.SugaredLogger
	PollConfigLog          *zap.SugaredLogger
	NrfRegistrationLog     *zap.SugaredLogger
	atomicLevel            zap.AtomicLevel
)

const (
	FieldSupi string = "supi"
)

func init() {
	atomicLevel = zap.NewAtomicLevelAt(zap.InfoLevel)
	config := zap.Config{
		Level:            atomicLevel,
		Development:      false,
		Encoding:         "console",
		EncoderConfig:    zap.NewProductionEncoderConfig(),
		OutputPaths:      []string{"stdout"},
		ErrorOutputPaths: []string{"stderr"},
	}

	config.EncoderConfig.TimeKey = "timestamp"
	config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	config.EncoderConfig.LevelKey = "level"
	config.EncoderConfig.EncodeLevel = zapcore.CapitalLevelEncoder
	config.EncoderConfig.CallerKey = "caller"
	config.EncoderConfig.EncodeCaller = zapcore.ShortCallerEncoder
	config.EncoderConfig.MessageKey = "message"
	config.EncoderConfig.StacktraceKey = ""

	var err error
	log, err = config.Build()
	if err != nil {
		panic(err)
	}

	AppLog = log.Sugar().With("component", "PCF", "category", "App")
	InitLog = log.Sugar().With("component", "PCF", "category", "Init")
	CfgLog = log.Sugar().With("component", "PCF", "category", "CFG")
	HandlerLog = log.Sugar().With("component", "PCF", "category", "Handler")
	BdtpolicyLog = log.Sugar().With("component", "PCF", "category", "Bdtpolicy")
	AMpolicyLog = log.Sugar().With("component", "PCF", "category", "Ampolicy")
	PolicyAuthorizationLog = log.Sugar().With("component", "PCF", "category", "PolicyAuth")
	SMpolicyLog = log.Sugar().With("component", "PCF", "category", "SMpolicy")
	UtilLog = log.Sugar().With("component", "PCF", "category", "Util")
	CallbackLog = log.Sugar().With("component", "PCF", "category", "Callback")
	OamLog = log.Sugar().With("component", "PCF", "category", "OAM")
	CtxLog = log.Sugar().With("component", "PCF", "category", "Context")
	ConsumerLog = log.Sugar().With("component", "PCF", "category", "Consumer")
	GinLog = log.Sugar().With("component", "PCF", "category", "GIN")
	NotifyEventLog = log.Sugar().With("component", "PCF", "category", "NotifyEvent")
	ProducerLog = log.Sugar().With("component", "PCF", "category", "Producer")
	PollConfigLog = log.Sugar().With("component", "PCF", "category", "PollConfig")
	NrfRegistrationLog = log.Sugar().With("component", "PCF", "category", "NrfRegistration")
}

// SetLogLevel: set the log level (panic|fatal|error|warn|info|debug)
func SetLogLevel(level zapcore.Level) {
	InitLog.Infoln("set log level:", level)
	atomicLevel.SetLevel(level)
}
