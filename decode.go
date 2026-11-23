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
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
)

type BOMDecoder interface {
	Decode(bom *BOM) error
}

func NewBOMDecoder(reader io.Reader, format BOMFileFormat) BOMDecoder {
	if format == BOMFileFormatJSON {
		return &jsonBOMDecoder{reader: reader}
	}
	return &xmlBOMDecoder{reader: reader}
}

type jsonBOMDecoder struct {
	reader io.Reader
}

// Decode implements the BOMDecoder interface.
func (j jsonBOMDecoder) Decode(bom *BOM) error {
	if bom == nil {
		return fmt.Errorf("cannot decode into a nil BOM")
	}

	data, err := io.ReadAll(j.reader)
	if err != nil {
		return err
	}

	// Decode and validate a complete candidate before committing it to the
	// caller's BOM. A failed attempt cannot leave stale or partial content.
	var decoded BOM
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	if err := validateVulnerabilities(&decoded, "decode"); err != nil {
		return err
	}

	*bom = decoded
	return nil
}

type xmlBOMDecoder struct {
	reader io.Reader
}

// Decode implements the BOMDecoder interface.
func (x xmlBOMDecoder) Decode(bom *BOM) error {
	if bom == nil {
		return fmt.Errorf("cannot decode into a nil BOM")
	}

	// As with JSON, never mutate the caller's BOM until the whole document has
	// been decoded and validated.
	var decoded BOM
	err := xml.NewDecoder(x.reader).Decode(&decoded)
	if err != nil {
		return err
	}

	for specVersion, xmlNs := range xmlNamespaces {
		if xmlNs == decoded.XMLNS {
			decoded.SpecVersion = specVersion
			break
		}
	}

	if err := validateVulnerabilities(&decoded, "decode"); err != nil {
		return err
	}

	*bom = decoded
	return nil
}
