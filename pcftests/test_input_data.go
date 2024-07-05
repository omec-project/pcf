// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2024 Canonical Ltd.
/*
 *  Sample input data for tests
 */

package pcftests

// Data in JSON format which is to be decoded
// OperationType - Add
var Data = []byte(`{
	"NetworkSlice": [
		{
		 "Name": "siteOne",
		 "Nssai": {"Sst": "010203", "Sd": "1"},
		 "Site": {
			"SiteName": "siteOne",
			"Gnb": [
				{"Name": "gnb1", "Tac": 1}, 
				{"Name": "gnb2", "Tac": 2}
			],
			"Plmn": {"mcc": "208", "mnc": "93"}
		  },
		 "DeviceGroup": [
		 	    {"Name": "dg1", 
				"IpDomainDetails": {
				"DnnName": "internet",
				"UeDnnQos": {"DnnMbrUplink": 100000, "DnnMbrDownlink": 50000, "TrafficClass": {"Qci": 9, "Arp": 6}}
				},
				"Imsi": ["123456789123456", "123456789123457", "123456789123458"]}
		 ],
		 "AppFilters": {
			"PccRuleBase": [{"FlowInfos": [{"FlowDesc": "permit out ip from 8.8.8.8/32 to assigned", "TosTrafficClass": "IPV4", "FlowDir": 2}], "RuleId": "rule1", "Priority": 15, "Qos": {"Var5qi": 8}},
						   {"FlowInfos": [{"FlowDesc": "permit out ip from any to assigned", "TosTrafficClass": "IPV4", "FlowDir": 2}], "RuleId": "rule2", "Priority": 25}]
		 },
		 "OperationType": 0
		}
		]}`)

// UData OperationType: Update
var UData = []byte(`{
	"NetworkSlice": [
		{
		 "Name": "siteOne",
		 "Nssai": {"Sst": "010203", "Sd": "1"},
		 "Site": {
			"SiteName": "siteOne",
			"Gnb": [
				{"Name": "gnb1", "Tac": 1}, 
				{"Name": "gnb2", "Tac": 2}
			],
			"Plmn": {"mcc": "208", "mnc": "93"}
		  },
		 "DeviceGroup": [
		 	    {"Name": "dg1", 
				"IpDomainDetails": {
				"DnnName": "internet",
				"UeDnnQos": {"DnnMbrUplink": 20000, "DnnMbrDownlink": 80000, "TrafficClass": {"Qci": 9, "Arp": 6}}
				},
				"Imsi": ["123456789123456", "123456789123457", "123456789123458", "123456789123459", "123456789123460"]}
		 ],
		 "AppFilters": {
			"PccRuleBase": [{"FlowInfos": [{"FlowDesc": "permit out ip from 8.8.8.8/32 to assigned", "TosTrafficClass": "IPV4", "FlowDir": 2}], "RuleId": "rule1", "Priority": 15, "Qos": {"Var5qi": 8}},
						   {"FlowInfos": [{"FlowDesc": "permit out ip from any to assigned", "TosTrafficClass": "IPV4", "FlowDir": 2}], "RuleId": "rule2", "Priority": 25}]
		 },
		 "OperationType": 1,
		 "AddUpdatedImsis": ["123456789123459", "123456789123460"]
		}
		]}`)

// UData1 OperationType: Update
var UData1 = []byte(`{
	"NetworkSlice": [
		{
		 "Name": "siteOne",
		 "Nssai": {"Sst": "010203", "Sd": "1"},
		 "Site": {
			"SiteName": "siteOne",
			"Gnb": [
				{"Name": "gnb1", "Tac": 1}, 
				{"Name": "gnb2", "Tac": 2}
			],
			"Plmn": {"mcc": "208", "mnc": "93"}
		  },
		 "DeviceGroup": [
		 	    {"Name": "dg1", 
				"IpDomainDetails": {
				"DnnName": "internet",
				"UeDnnQos": {"DnnMbrUplink": 100000, "DnnMbrDownlink": 50000, "TrafficClass": {"Qci": 9, "Arp": 6}}
				},
				"Imsi": ["123456789123456", "123456789123459", "123456789123460", "123456789123461"]}
		 ],
		 "AppFilters": {
			"PccRuleBase": [{"FlowInfos": [{"FlowDesc": "permit out ip from 8.8.8.8/32 to assigned", "TosTrafficClass": "IPV4", "FlowDir": 2}], "RuleId": "rule1", "Priority": 15, "Qos": {"Var5qi": 8}},
						   {"FlowInfos": [{"FlowDesc": "permit out ip from any to assigned", "TosTrafficClass": "IPV4", "FlowDir": 2}], "RuleId": "rule2", "Priority": 25}]
		 },
		 "OperationType": 1,
		 "AddUpdatedImsis": ["123456789123461"],
		 "DeletedImsis": ["123456789123457", "123456789123458"]
		}
		]}`)

// DelData OperationType: Delete
var DelData = []byte(`{
	"NetworkSlice": [
		{
		 "Name": "siteOne",
		 "Nssai": {"Sst": "010203", "Sd": "1"},
		 "Site": {
			"SiteName": "siteOne",
			"Gnb": [
				{"Name": "gnb1", "Tac": 1}, 
				{"Name": "gnb2", "Tac": 2}
			],
			"Plmn": {"mcc": "208", "mnc": "93"}
		  },
		 "DeviceGroup": [
		 	    {"Name": "dg1", 
				"IpDomainDetails": {
				"DnnName": "internet",
				"UeDnnQos": {"DnnMbrUplink": 100000, "DnnMbrDownlink": 50000, "TrafficClass": {"Qci": 9, "Arp": 6}}
				},
				"Imsi": ["123456789123456", "123456789123457", "123456789123458", "123456789123459", "123456789123460"]}
		 ],
		 "AppFilters": {
			"PccRuleBase": [{"FlowInfos": [{"FlowDesc": "permit out ip from 8.8.8.8/32 to assigned", "TosTrafficClass": "IPV4", "FlowDir": 2}], "RuleId": "rule1", "Priority": 15, "Qos": {"Var5qi": 8}},
						   {"FlowInfos": [{"FlowDesc": "permit out ip from any to assigned", "TosTrafficClass": "IPV4", "FlowDir": 2}], "RuleId": "rule2", "Priority": 25}]
		 },
		 "OperationType": 2,
		 "DeletedImsis": ["123456789123456", "123456789123457", "123456789123458", "123456789123459", "123456789123460", "123456789123461"]
		}
		]}`)
