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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLocalBOMTransaction_ValidateCollectsAllSchemaErrors(t *testing.T) {
	input := []byte(`{
		"bomFormat": "NotCycloneDX",
		"specVersion": "1.7",
		"version": 1,
		"components": [
			{"name": "first-healthy-component"},
			{"name": "second-component"}
		]
	}`)

	transaction := NewBOMTransaction(input, BOMFileFormatJSON)
	err := transaction.Validate()
	require.Error(t, err)

	report := transaction.Report()
	assert.False(t, report.Clean)
	assert.False(t, report.Copied)
	assert.Equal(t, BOMTransactionStageValidate, report.Stage)
	assert.GreaterOrEqual(t, len(report.ValidationErrors), 2)
	assert.Equal(t, report.InputDigest, transaction.Digest())
	assert.Equal(t, len(input), report.InputSize)

	copied, copyErr := transaction.Copy()
	require.ErrorIs(t, copyErr, ErrBOMTransactionNotValidated)
	assert.Nil(t, copied)
	assert.Empty(t, transaction.Output())
}

func TestLocalValidateBOMObject_CollectsAllSchemaErrors(t *testing.T) {
	bom := NewBOM()
	bom.Components = &[]Component{
		{Name: "first-healthy-component"},
		{Name: "second-component"},
	}

	report, err := ValidateBOMObject(bom, BOMFileFormatJSON)
	require.Error(t, err)
	assert.False(t, report.Clean)
	assert.False(t, report.Copied)
	assert.GreaterOrEqual(t, len(report.ValidationErrors), 2)
	assert.NotEmpty(t, report.InputDigest)
}

func TestLocalBOMTransaction_ValidBOMSharesDigestValidationAndCopy(t *testing.T) {
	input, err := os.ReadFile("./testdata/valid-bom.json")
	require.NoError(t, err)

	transaction := NewBOMTransaction(input, BOMFileFormatJSON)
	require.NoError(t, transaction.Validate())

	expectedDigest := sha256.Sum256(input)
	report := transaction.Report()
	assert.True(t, report.Clean)
	assert.True(t, report.Copied)
	assert.Equal(t, BOMTransactionStageValidated, report.Stage)
	assert.Equal(t, hex.EncodeToString(expectedDigest[:]), report.InputDigest)
	assert.Equal(t, SpecVersion1_6, report.InputSpecVersion)
	assert.Empty(t, report.ValidationErrors)

	copied, err := transaction.Copy()
	require.NoError(t, err)
	require.NotNil(t, copied)
	assert.Equal(t, SpecVersion1_6, copied.SpecVersion)

	// Mutating the returned copy must not leak back into the transaction.
	(*copied.Components)[0].Name = "mutated"
	again, err := transaction.Copy()
	require.NoError(t, err)
	assert.NotEqual(t, "mutated", (*again.Components)[0].Name)
}

func TestLocalBOMTransaction_EncodePublishesRequestedVersion(t *testing.T) {
	input, err := os.ReadFile("./testdata/valid-bom.xml")
	require.NoError(t, err)

	transaction := NewBOMTransaction(input, BOMFileFormatXML)
	require.NoError(t, transaction.Validate())

	var output bytes.Buffer
	require.NoError(t, transaction.Encode(&output, SpecVersion1_3))
	require.NotEmpty(t, output.Bytes())

	report := transaction.Report()
	assert.True(t, report.Clean)
	assert.Equal(t, BOMTransactionStageEncoded, report.Stage)
	assert.Equal(t, SpecVersion1_6, report.InputSpecVersion)
	assert.Equal(t, SpecVersion1_3, report.OutputSpecVersion)
	expectedDigest := sha256.Sum256(output.Bytes())
	assert.Equal(t, hex.EncodeToString(expectedDigest[:]), report.OutputDigest)
	assert.Equal(t, output.Bytes(), transaction.Output())

	var decoded BOM
	require.NoError(t, NewBOMDecoder(bytes.NewReader(output.Bytes()), BOMFileFormatXML).Decode(&decoded))
	assert.Equal(t, SpecVersion1_3, decoded.SpecVersion)
}

func TestLocalBOMTransaction_EncodeFailurePublishesNothing(t *testing.T) {
	input := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.7","version":1}`)
	transaction := NewBOMTransaction(input, BOMFileFormatJSON)
	require.NoError(t, transaction.Validate())

	var output bytes.Buffer
	err := transaction.Encode(&output, SpecVersion(99))
	require.ErrorIs(t, err, ErrBOMUnsupportedSpecVersion)
	assert.Empty(t, output.Bytes())

	report := transaction.Report()
	assert.False(t, report.Clean)
	assert.Zero(t, report.OutputSpecVersion)
	assert.Empty(t, report.OutputDigest)
	assert.Equal(t, BOMTransactionStageConvert, report.Stage)
	assert.Equal(t, SpecVersion1_7, report.InputSpecVersion)
	assert.Empty(t, transaction.Output())

	// A failed output must not poison the validated copy. Retrying against a
	// supported version produces the complete output.
	require.NoError(t, transaction.Encode(&output, SpecVersion1_5))
	assert.NotEmpty(t, output.Bytes())
	assert.True(t, transaction.Report().Clean)
	assert.Equal(t, SpecVersion1_5, transaction.Report().OutputSpecVersion)
}

func TestLocalBOMTransaction_ConflictingVersionIsNeverClean(t *testing.T) {
	input := []byte(`{
		"$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
		"bomFormat": "CycloneDX",
		"specVersion": "1.7",
		"version": 1
	}`)

	transaction := NewBOMTransaction(input, BOMFileFormatJSON)
	err := transaction.Validate()
	require.Error(t, err)
	require.ErrorContains(t, err, "conflicting specification version")

	report := transaction.Report()
	assert.False(t, report.Clean)
	assert.False(t, report.Copied)
	assert.Equal(t, BOMTransactionStageValidate, report.Stage)
	require.NotEmpty(t, report.ValidationErrors)
	assert.Contains(t, report.ValidationErrors[0].Message, "conflicting specification version")

	copied, copyErr := transaction.Copy()
	require.ErrorIs(t, copyErr, ErrBOMTransactionNotValidated)
	assert.Nil(t, copied)
}

func TestLocalBOMTransaction_ConflictingXMLVersionIsNeverClean(t *testing.T) {
	input := []byte(`<?xml version="1.0"?>
		<bom
			xmlns="http://cyclonedx.org/schema/bom/1.7"
			xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
			xsi:schemaLocation="http://cyclonedx.org/schema/bom/1.6 http://cyclonedx.org/schema/bom/1.6.xsd"
			version="1">
		</bom>`)

	transaction := NewBOMTransaction(input, BOMFileFormatXML)
	err := transaction.Validate()
	require.Error(t, err)
	require.ErrorContains(t, err, "conflicting specification version")

	report := transaction.Report()
	assert.False(t, report.Clean)
	assert.False(t, report.Copied)
	assert.Equal(t, BOMTransactionStageValidate, report.Stage)
	assert.Equal(t, SpecVersion1_7, report.InputSpecVersion)
	assert.Nil(t, transaction.Output())
}

func TestLocalBOMReport_IsMachineReadable(t *testing.T) {
	input := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.7","version":1}`)
	transaction := NewBOMTransaction(input, BOMFileFormatJSON)
	require.NoError(t, transaction.Validate())

	data, err := json.Marshal(transaction.Report())
	require.NoError(t, err)
	assert.Contains(t, string(data), `"clean":true`)
	assert.Contains(t, string(data), `"copied":true`)
	assert.Contains(t, string(data), `"inputSpecVersion":"1.7"`)
	assert.Contains(t, string(data), `"inputDigest":"`)

	var output bytes.Buffer
	require.Error(t, transaction.Encode(&output, SpecVersion(99)))
	data, err = json.Marshal(transaction.Report())
	require.NoError(t, err)
	assert.Contains(t, string(data), `"clean":false`)
	assert.NotContains(t, string(data), `"outputSpecVersion"`)
	assert.Empty(t, output.Bytes())
}

func TestLocalBOMEncoder_EncodeDoesNotPublishPartialBOM(t *testing.T) {
	bom := NewBOM()
	bom.Formulation = &[]Formula{{
		Workflows: &[]Workflow{{
			Inputs: &[]TaskInput{{
				EnvironmentVars: &EnvironmentVariables{{
					Property: &Property{Name: "invalid", Value: "both"},
					Value:    "both",
				}},
			}},
		}},
	}}

	var output bytes.Buffer
	err := NewBOMEncoder(&output, BOMFileFormatXML).Encode(bom)
	require.Error(t, err)
	assert.Empty(t, output.Bytes())
}

func TestLocalBOMDecoder_FailureDoesNotPublishPartialBOM(t *testing.T) {
	existing := BOM{
		BOMFormat:    "kept",
		SpecVersion:  SpecVersion1_3,
		SerialNumber: "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
		Version:      42,
	}
	malformed := `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.7",
		"serialNumber": "urn:uuid:aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
		"version": "not-a-number"
	}`

	err := NewBOMDecoder(strings.NewReader(malformed), BOMFileFormatJSON).Decode(&existing)
	require.Error(t, err)
	assert.Equal(t, "kept", existing.BOMFormat)
	assert.Equal(t, SpecVersion1_3, existing.SpecVersion)
	assert.Equal(t, "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79", existing.SerialNumber)
	assert.Equal(t, 42, existing.Version)
}

func TestLocalBOMTransaction_EmptyBOMSupportedVersions(t *testing.T) {
	for version := SpecVersion1_0; version <= SpecVersion1_7; version++ {
		t.Run(version.String(), func(t *testing.T) {
			check := func(t *testing.T, format BOMFileFormat) {
				t.Helper()

				bom := NewBOM()
				bom.SpecVersion = version
				bom.JSONSchema = jsonSchemas[version]
				bom.XMLNS = xmlNamespaces[version]

				if format == BOMFileFormatXML && version < SpecVersion1_2 {
					// CycloneDX 1.0 and 1.1 XML schemas still require the
					// components element, even when it is empty.
					emptyComponents := []Component{}
					bom.Components = &emptyComponents
				}

				var encoded bytes.Buffer
				require.NoError(t, NewBOMEncoder(&encoded, format).Encode(bom))

				transaction := NewBOMTransaction(encoded.Bytes(), format)
				require.NoError(t, transaction.Validate())

				report := transaction.Report()
				assert.True(t, report.Clean)
				assert.True(t, report.Copied)
				assert.Equal(t, version, report.InputSpecVersion)
				assert.Equal(t, len(encoded.Bytes()), report.InputSize)

				copied, err := transaction.Copy()
				require.NoError(t, err)
				assert.Equal(t, version, copied.SpecVersion)
			}

			t.Run("xml", func(t *testing.T) {
				check(t, BOMFileFormatXML)
			})
			if version >= SpecVersion1_2 {
				t.Run("json", func(t *testing.T) {
					check(t, BOMFileFormatJSON)
				})
			}
		})
	}
}

func TestLocalBOMTransaction_EncodeEmptyBOMAcrossVersions(t *testing.T) {
	source := NewBOM()
	var input bytes.Buffer
	require.NoError(t, NewBOMEncoder(&input, BOMFileFormatXML).Encode(source))

	for version := SpecVersion1_0; version <= SpecVersion1_7; version++ {
		t.Run(version.String(), func(t *testing.T) {
			transaction := NewBOMTransaction(input.Bytes(), BOMFileFormatXML)
			require.NoError(t, transaction.Validate())

			var output bytes.Buffer
			require.NoError(t, transaction.Encode(&output, version))
			require.NotEmpty(t, output.Bytes())

			report := transaction.Report()
			assert.True(t, report.Clean)
			assert.Equal(t, version, report.OutputSpecVersion)
			assert.NotEmpty(t, report.OutputDigest)

			var decoded BOM
			require.NoError(t, NewBOMDecoder(bytes.NewReader(output.Bytes()), BOMFileFormatXML).Decode(&decoded))
			assert.Equal(t, version, decoded.SpecVersion)
		})
	}
}

func TestLocalBOMEncoder_EncodeVersionKeepsLegacyErrorText(t *testing.T) {
	err := NewBOMEncoder(io.Discard, BOMFileFormatJSON).EncodeVersion(NewBOM(), SpecVersion1_1)
	require.EqualError(
		t,
		err,
		"json format is not supported for specification versions lower than 1.2",
	)
}

func TestLocalBOMCopy_PreservesZeroValuesAndEmptySlices(t *testing.T) {
	zero := 0.0
	empty := []Property{}

	bom := NewBOM()
	bom.Components = &[]Component{{
		Type:       ComponentTypeLibrary,
		Name:       "empty-slice",
		Properties: &empty,
	}}
	bom.Vulnerabilities = &[]Vulnerability{{
		ID:      "CVE-0000-0000",
		Ratings: &[]VulnerabilityRating{{Score: &zero}},
	}}

	copied, err := bom.Copy()
	require.NoError(t, err)
	require.NotNil(t, copied)

	require.NotNil(t, copied.Components)
	require.NotNil(t, (*copied.Components)[0].Properties)
	assert.Empty(t, *(*copied.Components)[0].Properties)

	require.NotNil(t, copied.Vulnerabilities)
	require.NotNil(t, (*copied.Vulnerabilities)[0].Ratings)
	require.NotNil(t, (*(*copied.Vulnerabilities)[0].Ratings)[0].Score)
	assert.Zero(t, *(*(*copied.Vulnerabilities)[0].Ratings)[0].Score)

	// Ensure nested pointers are not shared with the source BOM.
	one := 1.0
	(*(*copied.Vulnerabilities)[0].Ratings)[0].Score = &one
	assert.NotNil(t, (*(*bom.Vulnerabilities)[0].Ratings)[0].Score)
	assert.Zero(t, *(*(*bom.Vulnerabilities)[0].Ratings)[0].Score)
}

type localTransactionFailingWriter struct{}

func (localTransactionFailingWriter) Write(_ []byte) (int, error) {
	return 0, errors.New("write failed")
}

func TestLocalBOMTransaction_WriteFailureIsNotClean(t *testing.T) {
	input := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.7","version":1}`)
	transaction := NewBOMTransaction(input, BOMFileFormatJSON)
	require.NoError(t, transaction.Validate())

	err := transaction.Encode(localTransactionFailingWriter{}, SpecVersion1_7)
	require.EqualError(t, err, "write failed")

	report := transaction.Report()
	assert.False(t, report.Clean)
	assert.Equal(t, BOMTransactionStageWrite, report.Stage)
	assert.Zero(t, report.OutputSpecVersion)
	assert.Empty(t, report.OutputDigest)
	assert.Empty(t, transaction.Output())
}
