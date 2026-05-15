// SPDX-FileCopyrightText: 2025 Intel Corporation
// Copyright 2019 Communication Service/Software Laboratory, National Chiao Tung University (free5gc.org)
//
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// A string used to indicate the features supported by an API that is used as
// defined in clause  6.6 in 3GPP TS 29.500. The string shall contain a bitmask
// indicating supported features in  hexadecimal representation Each character
// in the string shall take a value of \"0\" to \"9\",  \"a\" to \"f\" or \"A\"
// to \"F\" and shall represent the support of 4 features as described in table
// 5.2.2-3. The most significant character representing the highest-numbered
// features shall appear first in the string, and the character representing
// features 1 to 4 shall appear last in the string. The list of features and
// their numbering (starting with 1) are defined separately for each API. If the
// string contains a lower number of characters than there are  defined features
// for an API, all features that would be represented by characters that are not
// present in the string are not supported.
// SupportedFeature represents a hex string for API feature support
type SupportedFeature string

// NewSupportedFeature - new SupportedFeature from string
func NewSupportedFeature(suppFeat string) (*SupportedFeature, error) {
	// Pad odd-length strings with leading zero
	if len(suppFeat)%2 != 0 {
		suppFeat = "0" + suppFeat
	}

	// Validate hex string
	if _, err := hex.DecodeString(suppFeat); err != nil {
		return nil, fmt.Errorf("invalid hex string: %w", err)
	}

	// Convert to uppercase for consistency
	normalized := strings.ToUpper(suppFeat)
	sf := SupportedFeature(normalized)
	return &sf, nil
}

// NewEmptySupportedFeature - create empty SupportedFeature
func NewEmptySupportedFeature() *SupportedFeature {
	sf := SupportedFeature("")
	return &sf
}

// String - convert SupportedFeature to hex format
func (sf *SupportedFeature) String() string {
	if sf == nil {
		return ""
	}
	return string(*sf)
}

// GetFeature - get nth feature is supported
func (sf *SupportedFeature) GetFeature(n int) bool {
	if sf == nil || sf.String() == "" || n < 1 {
		return false
	}

	hexStr := sf.String()
	// padding for hex decode
	if len(hexStr)%2 != 0 {
		hexStr = "0" + hexStr
	}

	bytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return false
	}

	byteIndex := len(bytes) - ((n - 1) / 8) - 1
	bitShift := uint8((n - 1) % 8)

	if byteIndex < 0 {
		return false
	}

	return bytes[byteIndex]&(0x01<<bitShift) > 0
}

// NegotiateWith - Negotiate with other supported feature
func (sf *SupportedFeature) NegotiateWith(other *SupportedFeature) (*SupportedFeature, error) {
	if sf == nil || sf.String() == "" || other == nil || other.String() == "" {
		return NewEmptySupportedFeature(), nil
	}

	// Convert both to bytes for bitwise operations
	hexStrA := sf.String()
	if len(hexStrA)%2 != 0 {
		hexStrA = "0" + hexStrA
	}
	bytesA, err := hex.DecodeString(hexStrA)
	if err != nil {
		return nil, fmt.Errorf("failed to decode first feature: %w", err)
	}

	hexStrB := other.String()
	if len(hexStrB)%2 != 0 {
		hexStrB = "0" + hexStrB
	}
	bytesB, err := hex.DecodeString(hexStrB)
	if err != nil {
		return nil, fmt.Errorf("failed to decode second feature: %w", err)
	}

	var suppFeatA, suppFeatB []byte
	var negotiatedFeatureLength, lengthDiff int

	// padding short one
	if len(bytesA) < len(bytesB) {
		suppFeatA = bytesB
		suppFeatB = make([]byte, len(bytesB))
		lengthDiff = len(bytesB) - len(bytesA)
		copy(suppFeatB[lengthDiff:], bytesA)
		negotiatedFeatureLength = len(bytesB)
	} else {
		suppFeatA = bytesA
		suppFeatB = make([]byte, len(bytesA))
		lengthDiff = len(bytesA) - len(bytesB)
		copy(suppFeatB[lengthDiff:], bytesB)
		negotiatedFeatureLength = len(bytesA)
	}

	negotiateFeature := make([]byte, negotiatedFeatureLength)

	for i := 0; i < negotiatedFeatureLength; i++ {
		negotiateFeature[i] = suppFeatA[i] & suppFeatB[i]
	}

	// Convert back to hex string
	result := strings.ToUpper(hex.EncodeToString(negotiateFeature))
	sfPtr := SupportedFeature(result)
	return &sfPtr, nil
}

// IsEmpty - check if SupportedFeature is empty or nil
func (sf *SupportedFeature) IsEmpty() bool {
	return sf == nil || sf.String() == ""
}

// Equal - check if two SupportedFeatures are equal
func (sf *SupportedFeature) Equal(other *SupportedFeature) bool {
	if sf == nil && other == nil {
		return true
	}
	if sf == nil || other == nil {
		return false
	}
	return strings.EqualFold(sf.String(), other.String())
}
