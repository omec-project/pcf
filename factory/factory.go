// Copyright (C) 2026 Intel Corporation
// SPDX-FileCopyrightText: 2025 Canonical Ltd.
// Copyright 2019 free5GC.org
// SPDX-License-Identifier: Apache-2.0

package factory

import (
	"github.com/omec-project/pcf/logger"
	"github.com/omec-project/util/nfconfig"
)

var PcfConfig Config

// TODO: Support configuration update from REST api
func InitConfigFactory(f string) error {
	PcfConfig = Config{}

	if err := nfconfig.LoadYAML(f, &PcfConfig); err != nil {
		return err
	}
	webuiUri, err := nfconfig.ResolveWebuiUri(PcfConfig.Configuration.WebuiUri, logger.CfgLog)
	if err != nil {
		return err
	}
	PcfConfig.Configuration.WebuiUri = webuiUri
	return nil
}

func CheckConfigVersion() error {
	return nfconfig.CheckVersion(PcfConfig.GetVersion(), PCF_EXPECTED_CONFIG_VERSION, logger.CfgLog)
}
