// This file is part of CycloneDX Go
//
// Licensed under the Apache License, Version 2.0 (the “License”);
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an “AS IS” BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) OWASP Foundation. All Rights Reserved.

package cyclonedx

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewBOMDecoder(t *testing.T) {
	assert.IsType(t, &jsonBOMDecoder{}, NewBOMDecoder(nil, BOMFileFormatJSON))
	assert.IsType(t, &xmlBOMDecoder{}, NewBOMDecoder(nil, BOMFileFormatXML))
}

func TestBOMDecoder_Decode_SupportedSpecVersions(t *testing.T) {
	for version := SpecVersion1_0; version <= SpecVersion1_7; version++ {
		t.Run(version.String(), func(t *testing.T) {
			t.Run("JSON", func(t *testing.T) {
				content := fmt.Sprintf(`{"bomFormat":"CycloneDX","specVersion":"%s"}`, version)

				var bom BOM
				err := NewBOMDecoder(strings.NewReader(content), BOMFileFormatJSON).Decode(&bom)
				require.NoError(t, err)
				require.Equal(t, version, bom.SpecVersion)
			})

			t.Run("XML", func(t *testing.T) {
				content := fmt.Sprintf(
					`<?xml version="1.0"?><bom xmlns="%s" version="1"></bom>`,
					xmlNamespaces[version],
				)

				var bom BOM
				err := NewBOMDecoder(strings.NewReader(content), BOMFileFormatXML).Decode(&bom)
				require.NoError(t, err)
				require.Equal(t, version, bom.SpecVersion)
			})
		})
	}
}

func TestXmlBOMDecoder_Decode_InvalidXML(t *testing.T) {
	var bom BOM
	err := NewBOMDecoder(strings.NewReader("invalid"), BOMFileFormatXML).Decode(&bom)
	require.Error(t, err)
}

func TestJsonBOMDecoder_Decode_InvalidJson(t *testing.T) {
	var bom BOM
	err := NewBOMDecoder(strings.NewReader("{}invalid"), BOMFileFormatJSON).Decode(&bom)
	require.Error(t, err)
}

func TestJsonBOMDecoder_Decode_DuplicateFields(t *testing.T) {
	testCases := []struct {
		name       string
		bomContent string
		categories []error
	}{
		{
			name:       "TopLevel",
			bomContent: `{"bomFormat":"CycloneDX","specVersion":"1.6","specVersion":"1.7"}`,
			categories: []error{ErrConflictingSpecVersion},
		},
		{
			name: "Nested",
			bomContent: `{
				"bomFormat":"CycloneDX",
				"specVersion":"1.6",
				"components":[{"type":"library","name":"a","bom-ref":"first","bom-ref":"second"}]
			}`,
		},
		{
			name: "EscapedKey",
			bomContent: `{
				"bomFormat":"CycloneDX",
				"specVersion":"1.6",
				"components":[{"type":"library","name":"a","bom-ref":"first","bom\u002dref":"second"}]
			}`,
		},
		{
			name: "NestedObject",
			bomContent: `{
				"bomFormat":"CycloneDX",
				"specVersion":"1.6",
				"metadata":{"component":{"type":"application","name":"a","name":"b"}}
			}`,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			var bom BOM
			err := NewBOMDecoder(strings.NewReader(testCase.bomContent), BOMFileFormatJSON).Decode(&bom)
			require.Error(t, err)
			require.ErrorIs(t, err, ErrDuplicateField)
			for _, category := range testCase.categories {
				require.ErrorIs(t, err, category)
			}
		})
	}
}

func TestJsonBOMDecoder_Decode_VersionDeclarations(t *testing.T) {
	t.Run("MatchingSchemaAndSpecVersion", func(t *testing.T) {
		var bom BOM
		err := NewBOMDecoder(strings.NewReader(`{
			"$schema":"https://cyclonedx.org/schema/bom-1.6.schema.json",
			"bomFormat":"CycloneDX",
			"specVersion":"1.6"
		}`), BOMFileFormatJSON).Decode(&bom)
		require.NoError(t, err)
		require.Equal(t, SpecVersion1_6, bom.SpecVersion)
	})

	t.Run("ConflictingSchemaAndSpecVersion", func(t *testing.T) {
		var bom BOM
		err := NewBOMDecoder(strings.NewReader(`{
			"$schema":"http://cyclonedx.org/schema/bom-1.5.schema.json",
			"bomFormat":"CycloneDX",
			"specVersion":"1.6"
		}`), BOMFileFormatJSON).Decode(&bom)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrConflictingSpecVersion)
	})

	t.Run("UnrecognizedSchema", func(t *testing.T) {
		var bom BOM
		err := NewBOMDecoder(strings.NewReader(`{
			"$schema":"https://example.com/schema.json",
			"bomFormat":"CycloneDX",
			"specVersion":"1.6"
		}`), BOMFileFormatJSON).Decode(&bom)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrInvalidSpecVersion)
	})

	t.Run("InvalidBOMFormat", func(t *testing.T) {
		var bom BOM
		err := NewBOMDecoder(strings.NewReader(`{
			"bomFormat":"SPDX",
			"specVersion":"1.6"
		}`), BOMFileFormatJSON).Decode(&bom)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrInvalidBOMFormat)
	})
}

func TestXmlBOMDecoder_Decode(t *testing.T) {
	t.Run("ShouldSetSpecVersion", func(t *testing.T) {
		testCases := []struct {
			bomContent  string
			specVersion SpecVersion
			wantErr     error
		}{
			{
				bomContent:  `<?xml version="1.0"?><bom version="1" xmlns="http://cyclonedx.org/schema/bom/1.0"></bom>`,
				specVersion: SpecVersion1_0,
			},
			{
				bomContent:  `<?xml version="1.0"?><bom version="1" xmlns="http://cyclonedx.org/schema/bom/1.1"></bom>`,
				specVersion: SpecVersion1_1,
			},
			{
				bomContent:  `<?xml version="1.0"?><bom version="1" xmlns="http://cyclonedx.org/schema/bom/1.2"></bom>`,
				specVersion: SpecVersion1_2,
			},
			{
				bomContent:  `<?xml version="1.0"?><bom version="1" xmlns="http://cyclonedx.org/schema/bom/1.3"></bom>`,
				specVersion: SpecVersion1_3,
			},
			{
				bomContent:  `<?xml version="1.0"?><bom version="1" xmlns="http://cyclonedx.org/schema/bom/1.4"></bom>`,
				specVersion: SpecVersion1_4,
			},
			{
				bomContent:  `<?xml version="1.0"?><bom version="1" xmlns="http://cyclonedx.org/schema/bom/666"></bom>`,
				specVersion: SpecVersion(0),
				wantErr:     ErrInvalidXMLNamespace,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.specVersion.String(), func(t *testing.T) {
				var bom BOM
				err := NewBOMDecoder(strings.NewReader(tc.bomContent), BOMFileFormatXML).Decode(&bom)
				if tc.wantErr != nil {
					require.Error(t, err)
					require.ErrorIs(t, err, tc.wantErr)
					return
				}
				require.NoError(t, err)
				require.Equal(t, tc.specVersion, bom.SpecVersion)
			})
		}
	})
}

func TestXmlBOMDecoder_Decode_DuplicateFields(t *testing.T) {
	testCases := []struct {
		name       string
		bomContent string
		categories []error
	}{
		{
			name:       "DuplicateAttribute",
			bomContent: `<?xml version="1.0"?><bom xmlns="http://cyclonedx.org/schema/bom/1.6" version="1" version="2"></bom>`,
		},
		{
			name:       "DuplicateNamespaceDeclaration",
			bomContent: `<?xml version="1.0"?><bom xmlns="http://cyclonedx.org/schema/bom/1.6" xmlns="http://cyclonedx.org/schema/bom/1.5"></bom>`,
			categories: []error{ErrConflictingXMLNamespace, ErrConflictingSpecVersion},
		},
		{
			name:       "DuplicateNestedAttribute",
			bomContent: `<?xml version="1.0"?><bom xmlns="http://cyclonedx.org/schema/bom/1.6"><components><component bom-ref="a" bom-ref="b"></component></components></bom>`,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			var bom BOM
			err := NewBOMDecoder(strings.NewReader(testCase.bomContent), BOMFileFormatXML).Decode(&bom)
			require.Error(t, err)
			require.ErrorIs(t, err, ErrDuplicateField)
			for _, category := range testCase.categories {
				require.ErrorIs(t, err, category)
			}
		})
	}
}

func TestXmlBOMDecoder_Decode_VersionDeclarations(t *testing.T) {
	t.Run("PrefixedNamespace", func(t *testing.T) {
		var bom BOM
		err := NewBOMDecoder(strings.NewReader(
			`<?xml version="1.0"?><cdx:bom xmlns:cdx="http://cyclonedx.org/schema/bom/1.5" version="1"></cdx:bom>`,
		), BOMFileFormatXML).Decode(&bom)
		require.NoError(t, err)
		require.Equal(t, SpecVersion1_5, bom.SpecVersion)
		require.Equal(t, xmlNamespaces[SpecVersion1_5], bom.XMLNS)
	})

	t.Run("MatchingSchemaLocation", func(t *testing.T) {
		var bom BOM
		err := NewBOMDecoder(strings.NewReader(
			`<?xml version="1.0"?><bom xmlns="http://cyclonedx.org/schema/bom/1.6" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://cyclonedx.org/schema/bom/1.6 http://cyclonedx.org/schema/bom/1.6.xsd" version="1"></bom>`,
		), BOMFileFormatXML).Decode(&bom)
		require.NoError(t, err)
		require.Equal(t, SpecVersion1_6, bom.SpecVersion)
	})

	t.Run("ConflictingSchemaLocation", func(t *testing.T) {
		var bom BOM
		err := NewBOMDecoder(strings.NewReader(
			`<?xml version="1.0"?><bom xmlns="http://cyclonedx.org/schema/bom/1.6" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://cyclonedx.org/schema/bom/1.5 http://cyclonedx.org/schema/bom/1.5.xsd" version="1"></bom>`,
		), BOMFileFormatXML).Decode(&bom)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrConflictingXMLNamespace)
		require.ErrorIs(t, err, ErrConflictingSpecVersion)
	})

	t.Run("ConflictingAliasNamespace", func(t *testing.T) {
		var bom BOM
		err := NewBOMDecoder(strings.NewReader(
			`<?xml version="1.0"?><bom xmlns="http://cyclonedx.org/schema/bom/1.6" xmlns:cdx="http://cyclonedx.org/schema/bom/1.5" version="1"></bom>`,
		), BOMFileFormatXML).Decode(&bom)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrConflictingXMLNamespace)
	})

	t.Run("NestedNamespaceConflict", func(t *testing.T) {
		var bom BOM
		err := NewBOMDecoder(strings.NewReader(
			`<?xml version="1.0"?><bom xmlns="http://cyclonedx.org/schema/bom/1.6"><metadata xmlns="http://cyclonedx.org/schema/bom/1.5"></metadata></bom>`,
		), BOMFileFormatXML).Decode(&bom)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrConflictingXMLNamespace)
	})
}
