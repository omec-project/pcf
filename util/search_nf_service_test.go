// Copyright (c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package util

import (
	"testing"

	"github.com/omec-project/openapi/v2"
	"github.com/omec-project/openapi/v2/models"
)

func TestSearchNFServiceUri_EmptyIpEndPointsDoesNotPanic(t *testing.T) {
	nfURI := SearchNFServiceUri(models.NFProfileDiscovery{
		NfServices: []models.NFService{{
			ServiceName:     models.SERVICENAME_NUDR_DR,
			NfServiceStatus: models.NFSERVICESTATUS_REGISTERED,
			Scheme:          models.URISCHEME_HTTPS,
			IpEndPoints:     []models.IpEndPoint{},
		}},
	}, models.SERVICENAME_NUDR_DR, models.NFSERVICESTATUS_REGISTERED)

	if nfURI != "" {
		t.Fatalf("expected empty URI, got %q", nfURI)
	}
}

func TestSearchNFServiceUri_UsesNfServiceListWhenNfServicesEmpty(t *testing.T) {
	nfServiceList := map[string]models.NFService{
		"service-1": {
			ServiceName:     models.SERVICENAME_NUDR_DR,
			NfServiceStatus: models.NFSERVICESTATUS_REGISTERED,
			Scheme:          models.URISCHEME_HTTPS,
			IpEndPoints: []models.IpEndPoint{
				{Ipv4Address: openapi.PtrString("10.0.0.2"), Port: openapi.PtrInt32(9443)},
			},
		},
	}

	nfURI := SearchNFServiceUri(models.NFProfileDiscovery{
		NfServiceList: &nfServiceList,
	}, models.SERVICENAME_NUDR_DR, models.NFSERVICESTATUS_REGISTERED)

	wantURI := "https://10.0.0.2:9443"
	if nfURI != wantURI {
		t.Fatalf("expected URI %q, got %q", wantURI, nfURI)
	}
}

func TestSearchNFServiceUri_NfServiceListTakesPrecedenceOverNfServices(t *testing.T) {
	nfServiceList := map[string]models.NFService{
		"service-1": {
			ServiceName:     models.SERVICENAME_NUDR_DR,
			NfServiceStatus: models.NFSERVICESTATUS_REGISTERED,
			Scheme:          models.URISCHEME_HTTPS,
			IpEndPoints: []models.IpEndPoint{
				{Ipv4Address: openapi.PtrString("10.0.0.2"), Port: openapi.PtrInt32(9443)},
			},
		},
	}

	nfURI := SearchNFServiceUri(models.NFProfileDiscovery{
		NfServices: []models.NFService{{
			ServiceName:     models.SERVICENAME_NUDR_DR,
			NfServiceStatus: models.NFSERVICESTATUS_REGISTERED,
			Scheme:          models.URISCHEME_HTTP,
			IpEndPoints: []models.IpEndPoint{
				{Ipv4Address: openapi.PtrString("10.0.0.1"), Port: openapi.PtrInt32(8080)},
			},
		}},
		NfServiceList: &nfServiceList,
	}, models.SERVICENAME_NUDR_DR, models.NFSERVICESTATUS_REGISTERED)

	wantURI := "https://10.0.0.2:9443"
	if nfURI != wantURI {
		t.Fatalf("expected NfServiceList entry %q to take precedence, got %q", wantURI, nfURI)
	}
}

func TestSearchNFServiceUri_NfServiceListSelectionIsDeterministic(t *testing.T) {
	nfServiceList := map[string]models.NFService{
		"service-b": {
			ServiceName:     models.SERVICENAME_NUDR_DR,
			NfServiceStatus: models.NFSERVICESTATUS_REGISTERED,
			Scheme:          models.URISCHEME_HTTPS,
			IpEndPoints: []models.IpEndPoint{
				{Ipv4Address: openapi.PtrString("10.0.0.2"), Port: openapi.PtrInt32(9443)},
			},
		},
		"service-a": {
			ServiceName:     models.SERVICENAME_NUDR_DR,
			NfServiceStatus: models.NFSERVICESTATUS_REGISTERED,
			Scheme:          models.URISCHEME_HTTPS,
			IpEndPoints: []models.IpEndPoint{
				{Ipv4Address: openapi.PtrString("10.0.0.1"), Port: openapi.PtrInt32(9443)},
			},
		},
	}

	nfProfile := models.NFProfileDiscovery{NfServiceList: &nfServiceList}
	wantURI := "https://10.0.0.1:9443" // lexicographically smallest ServiceInstanceId ("service-a") wins

	for i := 0; i < 20; i++ {
		nfURI := SearchNFServiceUri(nfProfile, models.SERVICENAME_NUDR_DR, models.NFSERVICESTATUS_REGISTERED)
		if nfURI != wantURI {
			t.Fatalf("expected deterministic URI %q, got %q on iteration %d", wantURI, nfURI, i)
		}
	}
}
