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

import "fmt"

// BOMValidator validates serialized BOM documents against the CycloneDX
// schema for a given specification version.
type BOMValidator interface {
	Validate(bom []byte, specVersion SpecVersion) error
}

// validator is kept as an internal alias for existing package-level callers.
type validator = BOMValidator

// NewBOMValidator returns a schema validator for the given BOM format.
func NewBOMValidator(format BOMFileFormat) BOMValidator {
	switch format {
	case BOMFileFormatJSON:
		return newJSONValidator()
	case BOMFileFormatXML:
		return newXMLValidator()
	default:
		return unsupportedFormatValidator{format: format}
	}
}

type unsupportedFormatValidator struct {
	format BOMFileFormat
}

func (v unsupportedFormatValidator) Validate(_ []byte, _ SpecVersion) error {
	return fmt.Errorf("unsupported BOM file format %s", v.format)
}
