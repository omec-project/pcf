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

// standardisedNonGbr5QIs are the 5QI values that 3GPP TS 23.501 table 5.7.4-1 gives a Non-GBR
// resource type.
//
// Held as its own set rather than derived by negating standardisedGbr5QIs, because the negation
// answers a different question. A value outside the table is not Non-GBR — it is dynamically
// assigned, and carries its own QoS characteristics that may well include a guaranteed rate. A
// guarantee against 5QI 9 is a misconfiguration; a guarantee against a dynamically assigned value
// is how a guarantee is expressed where no standardised GBR 5QI fits, which is the case over a
// geostationary link, since no standardised GBR value has a packet delay budget that far.
var standardisedNonGbr5QIs = map[int32]bool{
	5: true, 6: true, 7: true, 8: true, 9: true, 10: true,
	69: true, 70: true,
	79: true, 80: true,
}

// IsStandardisedNonGbr5QI reports whether a 5QI is one of the standardised Non-GBR values, which
// is what makes a configured guaranteed rate against it a misconfiguration rather than a choice.
func IsStandardisedNonGbr5QI(fiveQI int32) bool {
	return standardisedNonGbr5QIs[fiveQI]
}
