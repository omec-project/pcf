// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package util

import (
	"testing"

	"github.com/omec-project/openapi/v2/models"
)

// The default 5QI at the mapping's call sites is only reached for a media type the map does not
// cover, so what keeps a valid media type off it is this map being total over the enum. A missing
// entry would otherwise surface as a 5QI of 0 — not an assigned value, and treated as GBR by the
// comparison the consumers of this table used before IsStandardisedGbr5QI.
func TestMediaTypeTo5qiMapCoversEveryMediaType(t *testing.T) {
	for _, medType := range models.AllowedMediaTypeEnumValues {
		fiveQI, ok := MediaTypeTo5qiMap[medType]
		if !ok {
			t.Errorf("media type %q has no 5QI, so it maps to 0", medType)

			continue
		}
		if fiveQI == 0 {
			t.Errorf("media type %q maps to a 5QI of 0, which TS 23.501 does not assign", medType)
		}
	}
}
