// SPDX-FileCopyrightText: 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"testing"
)

func TestNewSupportedFeature(t *testing.T) {
	suppFeat, err := NewSupportedFeature("03")
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if suppFeat.String() != "03" {
		t.Errorf("Expected '03', got '%s'", suppFeat.String())
	}

	suppFeat, err = NewSupportedFeature("03FF")
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if suppFeat.String() != "03FF" {
		t.Errorf("Expected '03FF', got '%s'", suppFeat.String())
	}

	suppFeat, err = NewSupportedFeature("0324")
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if suppFeat.String() != "0324" {
		t.Errorf("Expected '0324', got '%s'", suppFeat.String())
	}

	// Test case sensitivity - should normalize to uppercase
	suppFeat, err = NewSupportedFeature("03ff")
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if suppFeat.String() != "03FF" {
		t.Errorf("Expected '03FF', got '%s'", suppFeat.String())
	}

	// error case
	suppFeat, err = NewSupportedFeature("ZXCD")
	if err == nil {
		t.Error("Expected error for invalid hex string, got nil")
	}
	if suppFeat != nil {
		t.Errorf("Expected nil for invalid input, got %v", suppFeat)
	}
}

func TestGetFeatureOfSupportedFeature(t *testing.T) {
	suppFeat, err := NewSupportedFeature("1324")
	if err != nil {
		t.Fatalf("Failed to create new supported feature from string: %v", err)
	}

	testCases := []struct {
		feature  int
		expected bool
	}{
		{1, false},
		{2, false},
		{3, true},
		{4, false},
		{5, false},
		{6, true},
		{7, false},
		{8, false},
		{9, true},
		{10, true},
		{11, false},
		{12, false},
		{13, true},
		{14, false},
		{15, false},
		{16, false},
	}

	for _, tc := range testCases {
		result := suppFeat.GetFeature(tc.feature)
		if result != tc.expected {
			t.Errorf("GetFeature(%d): expected %t, got %t", tc.feature, tc.expected, result)
		}
	}
}

func TestStringOfSupportedFeature(t *testing.T) {
	suppFeat, err := NewSupportedFeature("1324")
	if err != nil {
		t.Fatalf("Failed to create new supported feature from string: %v", err)
	}
	if suppFeat.String() != "1324" {
		t.Errorf("Expected '1324', got '%s'", suppFeat.String())
	}

	// testing padding
	suppFeat, err = NewSupportedFeature("1")
	if err != nil {
		t.Fatalf("Failed to create new supported feature from string: %v", err)
	}
	expected := "01"
	if suppFeat.String() != expected {
		t.Errorf("Expected '%s', got '%s'", expected, suppFeat.String())
	}

	suppFeat, err = NewSupportedFeature("ABCDE")
	if err != nil {
		t.Fatalf("Failed to create new supported feature from string: %v", err)
	}
	expected = "0ABCDE"
	if suppFeat.String() != expected {
		t.Errorf("Expected '%s', got '%s'", expected, suppFeat.String())
	}
}

func TestNegotiateWithOfSupportedFeature(t *testing.T) {
	testCases := []struct {
		featA    string
		featB    string
		expected string
	}{
		{"0FFF", "1324", "0324"},
		{"0234", "0001", "0000"},
		{"FFFF", "F", "000F"},
		{"3000", "3", "0000"},
		{"23E3", "1", "0001"},
	}

	for _, tc := range testCases {
		suppFeatA, err := NewSupportedFeature(tc.featA)
		if err != nil {
			t.Fatalf("Failed to create supported feature A from '%s': %v", tc.featA, err)
		}

		suppFeatB, err := NewSupportedFeature(tc.featB)
		if err != nil {
			t.Fatalf("Failed to create supported feature B from '%s': %v", tc.featB, err)
		}

		negotiatedFeat, err := suppFeatA.NegotiateWith(suppFeatB)
		if err != nil {
			t.Fatalf("Failed to negotiate features '%s' and '%s': %v", tc.featA, tc.featB, err)
		}

		if negotiatedFeat.String() != tc.expected {
			t.Errorf("NegotiateWith('%s', '%s'): expected '%s', got '%s'",
				tc.featA, tc.featB, tc.expected, negotiatedFeat.String())
		}
	}
}
