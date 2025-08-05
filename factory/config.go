// SPDX-FileCopyrightText: 2025 Canonical Ltd.
// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
// Copyright 2019 free5GC.org
// SPDX-FileCopyrightText: 2024 Canonical Ltd.
// SPDX-License-Identifier: Apache-2.0
//

/*
 * PCF Configuration Factory
 */

package factory

import (
	"github.com/omec-project/util/logger"
)

const (
	PCF_EXPECTED_CONFIG_VERSION = "1.0.0"
)

type Config struct {
	Info          *Info          `yaml:"info"`
	Configuration *Configuration `yaml:"configuration"`
	Logger        *logger.Logger `yaml:"logger"`
	CfgLocation   string
}

type Info struct {
	Version     string `yaml:"version,omitempty"`
	Description string `yaml:"description,omitempty"`
}

const (
	PCF_DEFAULT_IPV4     = "127.0.0.7"
	PCF_DEFAULT_PORT     = "8000"
	PCF_DEFAULT_PORT_INT = 8000
)

type Configuration struct {
	PcfName                  string    `yaml:"pcfName,omitempty"`
	Sbi                      *Sbi      `yaml:"sbi,omitempty"`
	TimeFormat               string    `yaml:"timeFormat,omitempty"`
	DefaultBdtRefId          string    `yaml:"defaultBdtRefId,omitempty"`
	NrfUri                   string    `yaml:"nrfUri,omitempty"`
	WebuiUri                 string    `yaml:"webuiUri"`
	ServiceList              []Service `yaml:"serviceList,omitempty"`
	EnableNrfCaching         bool      `yaml:"enableNrfCaching"`
	NrfCacheEvictionInterval int       `yaml:"nrfCacheEvictionInterval,omitempty"`
}

type Service struct {
	ServiceName string `yaml:"serviceName"`
	SuppFeat    string `yaml:"suppFeat,omitempty"`
}

type Sbi struct {
	Scheme       string `yaml:"scheme"`
	TLS          *TLS   `yaml:"tls"`
	RegisterIPv4 string `yaml:"registerIPv4,omitempty"` // IP that is registered at NRF.
	// IPv6Addr  string `yaml:"ipv6Addr,omitempty"`
	BindingIPv4 string `yaml:"bindingIPv4,omitempty"` // IP used to run the server in the node.
	Port        int    `yaml:"port,omitempty"`
}

type TLS struct {
	PEM string `yaml:"pem,omitempty"`
	Key string `yaml:"key,omitempty"`
}

func (c *Config) GetVersion() string {
	if c.Info != nil && c.Info.Version != "" {
		return c.Info.Version
	}
	return ""
}
