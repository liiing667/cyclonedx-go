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
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRepro34349_DecodeRejectsDuplicateComponentRef(t *testing.T) {
	const input = `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.6",
		"components": [
			{"type": "library", "bom-ref": "shared", "name": "first", "version": "1.0.0"},
			{"type": "library", "bom-ref": "shared", "name": "second", "version": "2.0.0"}
		]
	}`

	bom := BOM{SerialNumber: "previous"}
	err := NewBOMDecoder(strings.NewReader(input), BOMFileFormatJSON).Decode(&bom)

	require.ErrorIs(t, err, ErrDuplicateBOMRef)
	require.Equal(t, "previous", bom.SerialNumber)
	require.Nil(t, bom.Components)

	// A failed decode must not poison the destination for the next attempt.
	const valid = `{"bomFormat": "CycloneDX", "specVersion": "1.6"}`
	err = NewBOMDecoder(strings.NewReader(valid), BOMFileFormatJSON).Decode(&bom)
	require.NoError(t, err)
	require.Empty(t, bom.SerialNumber)
	require.Nil(t, bom.Components)
}

func TestRepro34349_DecodeRetryReplacesDestination(t *testing.T) {
	bom := BOM{
		SerialNumber: "old",
		Metadata:     &Metadata{},
	}

	const input = `{"bomFormat": "CycloneDX", "specVersion": "1.6"}`
	err := NewBOMDecoder(strings.NewReader(input), BOMFileFormatJSON).Decode(&bom)

	require.NoError(t, err)
	require.Equal(t, SpecVersion1_6, bom.SpecVersion)
	require.Empty(t, bom.SerialNumber)
	require.Nil(t, bom.Metadata)
}

func TestRepro34349_EncodeVersionRejectsDuplicateRefWithoutMutation(t *testing.T) {
	components := []Component{
		{BOMRef: "shared", Type: ComponentTypeLibrary, Name: "first", Version: "1.0.0"},
		{BOMRef: "shared", Type: ComponentTypeLibrary, Name: "second", Version: "2.0.0"},
	}
	expected := append([]Component(nil), components...)

	bom := NewBOM()
	bom.Components = &components

	var buf bytes.Buffer
	err := NewBOMEncoder(&buf, BOMFileFormatJSON).EncodeVersion(bom, SpecVersion1_6)

	require.ErrorIs(t, err, ErrDuplicateBOMRef)
	require.Empty(t, buf.String())
	require.Equal(t, expected, *bom.Components)
}

func TestRepro34349_NestedDuplicateRefIsRejected(t *testing.T) {
	const input = `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.7",
		"components": [
			{
				"type": "application",
				"bom-ref": "outer",
				"name": "outer",
				"components": [
					{"type": "library", "bom-ref": "shared", "name": "nested"}
				]
			},
			{"type": "library", "bom-ref": "shared", "name": "top-level"}
		]
	}`

	var bom BOM
	err := NewBOMDecoder(strings.NewReader(input), BOMFileFormatJSON).Decode(&bom)

	require.ErrorIs(t, err, ErrDuplicateBOMRef)
	require.Contains(t, err.Error(), "components[0].components[0]")
	require.Contains(t, err.Error(), "components[1]")
}

func TestRepro34349_DanglingRefsAreRejected(t *testing.T) {
	bom := NewBOM()
	bom.Components = &[]Component{
		{BOMRef: "known", Type: ComponentTypeLibrary, Name: "known"},
	}
	bom.Dependencies = &[]Dependency{
		{
			Ref:          "known",
			Dependencies: &[]string{"missing"},
		},
	}

	err := ValidateBOMReferences(bom)
	require.ErrorIs(t, err, ErrDanglingBOMRef)
	require.Contains(t, err.Error(), "missing")
}

func TestRepro34349_CompositionRefsAreValidated(t *testing.T) {
	t.Run("duplicate identity", func(t *testing.T) {
		bom := NewBOM()
		bom.Compositions = &[]Composition{
			{BOMRef: "shared", Aggregate: CompositionAggregateComplete},
			{BOMRef: "shared", Aggregate: CompositionAggregateUnknown},
		}

		err := ValidateBOMReferences(bom)
		require.ErrorIs(t, err, ErrDuplicateBOMRef)
	})

	t.Run("dangling assembly", func(t *testing.T) {
		bom := NewBOM()
		bom.Components = &[]Component{
			{BOMRef: "known", Type: ComponentTypeLibrary, Name: "known"},
		}
		bom.Compositions = &[]Composition{
			{
				BOMRef:     "composition",
				Aggregate:  CompositionAggregateComplete,
				Assemblies: &[]BOMReference{"missing"},
			},
		}

		err := ValidateBOMReferences(bom)
		require.ErrorIs(t, err, ErrDanglingBOMRef)
	})
}

func TestRepro34349_LegacyVersionsAndNestedComponentsArePreserved(t *testing.T) {
	for version := SpecVersion1_0; version <= SpecVersion1_7; version++ {
		t.Run(version.String(), func(t *testing.T) {
			content := fmt.Sprintf(
				`<?xml version="1.0"?><bom xmlns="%s" version="1"></bom>`,
				xmlNamespaces[version],
			)

			var bom BOM
			err := NewBOMDecoder(strings.NewReader(content), BOMFileFormatXML).Decode(&bom)
			require.NoError(t, err)
			require.Equal(t, version, bom.SpecVersion)
		})
	}

	const nested = `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.7",
		"components": [
			{
				"type": "application",
				"bom-ref": "outer",
				"name": "outer",
				"components": [
					{"type": "library", "bom-ref": "inner", "name": "inner"}
				]
			}
		],
		"dependencies": [
			{"ref": "outer", "dependsOn": ["inner"]}
		]
	}`

	var bom BOM
	err := NewBOMDecoder(strings.NewReader(nested), BOMFileFormatJSON).Decode(&bom)
	require.NoError(t, err)
	require.NotNil(t, bom.Components)
	require.Len(t, *bom.Components, 1)
	require.NotNil(t, (*bom.Components)[0].Components)
	require.Equal(t, "inner", (*(*bom.Components)[0].Components)[0].BOMRef)
}

func TestRepro34349_EncodeVersionLegacyBoundaries(t *testing.T) {
	bom := NewBOM()
	bom.Components = &[]Component{
		{
			BOMRef:     "outer",
			Type:       ComponentTypeApplication,
			Name:       "outer",
			Components: &[]Component{
				{BOMRef: "inner", Type: ComponentTypeLibrary, Name: "inner"},
			},
		},
	}
	bom.Dependencies = &[]Dependency{
		{Ref: "outer", Dependencies: &[]string{"inner"}},
	}

	for version := SpecVersion1_0; version <= SpecVersion1_7; version++ {
		t.Run(version.String(), func(t *testing.T) {
			var buf bytes.Buffer
			err := NewBOMEncoder(&buf, BOMFileFormatXML).EncodeVersion(bom, version)
			require.NoError(t, err)
			require.NotEmpty(t, buf.String())
		})
	}
}
