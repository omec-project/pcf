// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package context

// standardisedGbr5QIs are the 5QI values that 3GPP TS 23.501 table 5.7.4-1 gives a GBR or
// delay-critical GBR resource type. Values outside this set are either standardised Non-GBR or
// dynamically assigned, and a dynamically assigned value carries its own QoS characteristics
// rather than referencing this table.
var standardisedGbr5QIs = map[int32]bool{
	// GBR
	1: true, 2: true, 3: true, 4: true,
	65: true, 66: true, 67: true,
	71: true, 72: true, 73: true, 74: true, 75: true, 76: true,
	// Delay-critical GBR
	82: true, 83: true, 84: true, 85: true, 86: true,
	87: true, 88: true, 89: true, 90: true,
}

// IsStandardisedGbr5QI reports whether a 5QI is one of the standardised GBR values.
//
// The test this replaces was 5QI <= 4, which is not the 3GPP definition and mishandled every
// standardised GBR value above 4.
func IsStandardisedGbr5QI(fiveQI int32) bool {
	return standardisedGbr5QIs[fiveQI]
}
