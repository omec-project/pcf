// Copyright (c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package util

import (
	"testing"

	"github.com/omec-project/openapi/v2/models"
	pcfContext "github.com/omec-project/pcf/context"
	"github.com/omec-project/pcf/factory"
)

func TestInitPcfContext_InvalidSupportedFeatureFallsBackToEmpty(t *testing.T) {
	originalConfig := factory.PcfConfig
	defer func() { factory.PcfConfig = originalConfig }()

	factory.PcfConfig = factory.Config{
		Info: &factory.Info{Version: "1.0.0", Description: "test"},
		Configuration: &factory.Configuration{
			Sbi:         &factory.Sbi{Scheme: "https", RegisterIPv4: "127.0.0.1", BindingIPv4: "127.0.0.1", Port: 8000},
			ServiceList: []factory.Service{{ServiceName: string(models.SERVICENAME_NPCF_POLICYAUTHORIZATION), SuppFeat: "ZZ"}},
		},
	}

	ctx := &pcfContext.PCFContext{
		NfService:      make(map[models.ServiceName]models.NFService),
		PcfServiceUris: make(map[models.ServiceName]string),
		PcfSuppFeats:   make(map[models.ServiceName]pcfContext.SupportedFeature),
	}

	InitPcfContext(ctx)
	g := ctx.PcfSuppFeats[models.SERVICENAME_NPCF_POLICYAUTHORIZATION]
	if got := g.String(); got != "" {
		t.Fatalf("expected empty supported feature, got %q", got)
	}
}
