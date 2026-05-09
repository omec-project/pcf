// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
// Copyright 2019 free5GC.org
// SPDX-FileCopyrightText: 2024 Canonical Ltd.
// SPDX-License-Identifier: Apache-2.0
//

package util

import (
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/omec-project/openapi/v2/models"
	pcfContext "github.com/omec-project/pcf/context"
	"github.com/omec-project/pcf/factory"
	"github.com/omec-project/pcf/logger"
)

// InitPcfContext Init PCF Context from config file
func InitPcfContext(context *pcfContext.PCFContext) {
	config := factory.PcfConfig
	logger.UtilLog.Infof("pcfconfig Info: Version[%s] Description[%s]", config.Info.Version, config.Info.Description)
	configuration := config.Configuration
	context.NfId = uuid.New().String()
	if configuration.PcfName != "" {
		context.Name = configuration.PcfName
	}

	sbi := configuration.Sbi
	context.NrfUri = configuration.NrfUri
	context.UriScheme = ""
	context.RegisterIPv4 = factory.PCF_DEFAULT_IPV4 // default localhost
	context.SBIPort = factory.PCF_DEFAULT_PORT_INT  // default port
	if sbi != nil {
		if sbi.Scheme != "" {
			context.UriScheme = models.UriScheme(sbi.Scheme)
		}
		if sbi.RegisterIPv4 != "" {
			context.RegisterIPv4 = sbi.RegisterIPv4
		}
		if sbi.Port != 0 {
			context.SBIPort = sbi.Port
		}
		if sbi.Scheme == "https" {
			context.UriScheme = models.URISCHEME_HTTPS
		} else {
			context.UriScheme = models.URISCHEME_HTTP
		}
		if tls := sbi.TLS; tls != nil {
			if tls.Key != "" {
				context.Key = tls.Key
			}
			if tls.PEM != "" {
				context.PEM = tls.PEM
			}
		}

		context.BindingIPv4 = os.Getenv(sbi.BindingIPv4)
		if context.BindingIPv4 != "" {
			logger.UtilLog.Infoln("parsing ServerIPv4 address from ENV variable")
		} else {
			context.BindingIPv4 = sbi.BindingIPv4
			if context.BindingIPv4 == "" {
				logger.UtilLog.Warnln("error parsing ServerIPv4 address as string. Using the 0.0.0.0 address as default")
				context.BindingIPv4 = "0.0.0.0"
			}
		}
	}
	context.EnableNrfCaching = configuration.EnableNrfCaching
	if configuration.EnableNrfCaching {
		if configuration.NrfCacheEvictionInterval == 0 {
			context.NrfCacheEvictionInterval = time.Duration(900) // 15 mins
		} else {
			context.NrfCacheEvictionInterval = time.Duration(configuration.NrfCacheEvictionInterval)
		}
	}
	serviceList := configuration.ServiceList
	context.InitNFService(serviceList, config.Info.Version)
	context.TimeFormat = configuration.TimeFormat
	context.DefaultBdtRefId = configuration.DefaultBdtRefId
	for _, service := range context.NfService {
		context.PcfServiceUris[service.ServiceName] = service.GetApiPrefix() + "/" + string(service.ServiceName) + "/" + (service.Versions)[0].ApiVersionInUri
		pcfSuppFeats, err := pcfContext.NewSupportedFeature(service.GetSupportedFeatures())
		if err != nil {
			logger.UtilLog.Errorf("NewSupportedFeature error: %+v", err)
			pcfSuppFeats = pcfContext.NewEmptySupportedFeature()
		}
		context.PcfSuppFeats[service.ServiceName] = *pcfSuppFeats
	}
}
