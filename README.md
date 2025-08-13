<!--
SPDX-FileCopyrightText: 2025 Canonical Ltd
SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
Copyright 2019 free5GC.org

SPDX-License-Identifier: Apache-2.0
-->
[![Go Report Card](https://goreportcard.com/badge/github.com/omec-project/pcf)](https://goreportcard.com/report/github.com/omec-project/pcf)

# pcf

The Policy Control Function (PCF) supports unified policy framework to govern
network behaviour, provides policy rules to Control Plane function(s) to enforce
them and Accesses subscription information relevant for policy decisions in a
Unified Data Repository (UDR)

The reference 3GPP specification for PCF are as follows
- PCC framework Specification 23.503,
- Session Management Policy Control - Specification 29.512
- Policy and Charging Control signalling flows and QoS parameter mapping (Spec 29.513)


## PCF Flow Diagram
![PCF Flow Diagram](/docs/images/README-PCF.png)

## Dynamic Network configuration (via webconsole)

PCF polls the webconsole every 5 seconds to fetch the latest policy configuration.

### Setting Up Polling

Include the `webuiUri` of the webconsole in the configuration file
```
configuration:
  ...
  webuiUri: https://webui:5001 # or http://webui:5001
  ...
```
The scheme (http:// or https://) must be explicitly specified. If no parameter is specified,
PCF will use `http://webui:5001` by default.

### HTTPS Support

If the webconsole is served over HTTPS and uses a custom or self-signed certificate,
you must install the root CA certificate into the trust store of the PCF environment.

Check the official guide for installing root CA certificates on Ubuntu:
[Install a Root CA Certificate in the Trust Store](https://documentation.ubuntu.com/server/how-to/security/install-a-root-ca-certificate-in-the-trust-store/index.html)

## Supported Features
- PCF provides Access and Mobility Management related policies to the AMF
Subscription Data retrieval and AM Policy management
- PCF provides Session Management Policy Control Service to the SMF Subscription
Data retrieval and SM Policy management
- Policy Control Function (PCF) shall support interactions with the access and
mobility policy enforcement in the AMF, through service-based interfaces

## Upcoming Changes in PCF
- Process configuration received from Configuration Service and prepare PCC
Rules, Session Rules and Qos Flows
- Send PCC Rules, Session Rules to SMF when a SMF Creates Policy subscriber
- Send notification towards SMF PDU Session when PCF detects any changes in
Subscriber’s Rule/Qos information.
- Dedicated QoS flows addition and removal through APIs

## 5G Compliance

Compliance of the 5G Network functions can be found at [5G Compliance](https://docs.sd-core.opennetworking.org/main/overview/3gpp-compliance-5g.html)


## Reach out to us through

1. #sdcore-dev channel in [Aether Project Slack](https://aether5g-project.slack.com)
2. Raise Github [issues](https://github.com/omec-project/pcf/issues/new)
