// SPDX-FileCopyrightText: 2025 Canonical Ltd.
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0
//

/*
 * PCF Configuration Factory
 */

package factory

import (
	"fmt"
	"net/url"
	"os"
	"sync"

	"github.com/omec-project/pcf/logger"
	"gopkg.in/yaml.v2"
)

var (
	PcfConfig  Config
	ConfigLock sync.Mutex
)

// TODO: Support configuration update from REST api
func InitConfigFactory(f string) error {
	content, err := os.ReadFile(f)
	if err != nil {
		return err
	}
	PcfConfig = Config{}

	if err = yaml.Unmarshal(content, &PcfConfig); err != nil {
		return err
	}

	if PcfConfig.Configuration.WebuiUri == "" {
		PcfConfig.Configuration.WebuiUri = "http://webui:5001"
		logger.CfgLog.Infof("webuiUri not set in configuration file. Using %v", PcfConfig.Configuration.WebuiUri)
		return nil
	}
	err = validateWebuiUri(PcfConfig.Configuration.WebuiUri)
	return err
}

func CheckConfigVersion() error {
	currentVersion := PcfConfig.GetVersion()

	if currentVersion != PCF_EXPECTED_CONFIG_VERSION {
		return fmt.Errorf("config version is [%s], but expected is [%s]",
			currentVersion, PCF_EXPECTED_CONFIG_VERSION)
	}

	logger.CfgLog.Infof("config version [%s]", currentVersion)

	return nil
}

func validateWebuiUri(uri string) error {
	parsedUrl, err := url.ParseRequestURI(uri)
	if err != nil {
		return err
	}
	if parsedUrl.Scheme != "http" && parsedUrl.Scheme != "https" {
		return fmt.Errorf("unsupported scheme for webuiUri: %s", parsedUrl.Scheme)
	}
	if parsedUrl.Hostname() == "" {
		return fmt.Errorf("missing host in webuiUri")
	}
	return nil
}
