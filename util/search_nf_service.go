// SPDX-FileCopyrightText: 2025 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

package util

import (
	"fmt"
	"sort"

	"github.com/omec-project/openapi/v2/models"
)

// SearchNFServiceUri returns NF Uri derived from NfProfile with corresponding service
func SearchNFServiceUri(nfProfile models.NFProfileDiscovery, serviceName models.ServiceName,
	nfServiceStatus models.NFServiceStatus,
) (nfUri string) {
	for _, service := range nfProfileServices(nfProfile) {
		if service.GetServiceName() == serviceName && service.GetNfServiceStatus() == nfServiceStatus {
			if nfProfile.GetFqdn() != "" {
				nfUri = nfProfile.GetFqdn()
			} else if service.GetFqdn() != "" {
				nfUri = service.GetFqdn()
			} else if service.GetApiPrefix() != "" {
				nfUri = service.GetApiPrefix()
			} else if len(service.GetIpEndPoints()) > 0 {
				point := service.GetIpEndPoints()[0]
				if point.GetIpv4Address() != "" {
					nfUri = getSbiUri(service.GetScheme(), point.GetIpv4Address(), point.GetPort())
				} else if len(nfProfile.GetIpv4Addresses()) != 0 {
					nfUri = getSbiUri(service.GetScheme(), nfProfile.GetIpv4Addresses()[0], point.GetPort())
				}
			}
		}
		if nfUri != "" {
			break
		}
	}

	return
}

// nfProfileServices returns nfProfile's NF services, preferring the TS 29.510
// Rel-16 nfServiceList over the deprecated nfServices array. NfServiceList is
// keyed by ServiceInstanceId in a map, so entries are sorted by that key to
// guarantee a deterministic service selection when multiple entries match.
func nfProfileServices(nfProfile models.NFProfileDiscovery) []models.NFService {
	nfServiceList := nfProfile.GetNfServiceList()
	if len(nfServiceList) == 0 {
		return nfProfile.GetNfServices()
	}
	instanceIds := make([]string, 0, len(nfServiceList))
	for instanceId := range nfServiceList {
		instanceIds = append(instanceIds, instanceId)
	}
	sort.Strings(instanceIds)
	services := make([]models.NFService, 0, len(nfServiceList))
	for _, instanceId := range instanceIds {
		services = append(services, nfServiceList[instanceId])
	}
	return services
}

func getSbiUri(scheme models.UriScheme, ipv4Address string, port int32) (uri string) {
	if port != 0 {
		uri = fmt.Sprintf("%s://%s:%d", scheme, ipv4Address, port)
	} else {
		switch scheme {
		case models.URISCHEME_HTTP:
			uri = fmt.Sprintf("%s://%s:80", scheme, ipv4Address)
		case models.URISCHEME_HTTPS:
			uri = fmt.Sprintf("%s://%s:443", scheme, ipv4Address)
		}
	}
	return
}
