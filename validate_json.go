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
	"embed"
	"fmt"

	"github.com/xeipuuv/gojsonschema"
)

//go:embed schema/*.json
var jsonSchemaFS embed.FS

// jsonSchemaFiles keeps the historical on-disk locations. Validation uses the
// embedded copies below so it does not depend on the process working
// directory or network access for companion schemas.
var jsonSchemaFiles = map[SpecVersion]string{
	SpecVersion1_2: "file://./schema/bom-1.2.schema.json",
	SpecVersion1_3: "file://./schema/bom-1.3.schema.json",
	SpecVersion1_4: "file://./schema/bom-1.4.schema.json",
	SpecVersion1_5: "file://./schema/bom-1.5.schema.json",
	SpecVersion1_6: "file://./schema/bom-1.6.schema.json",
	SpecVersion1_7: "file://./schema/bom-1.7.schema.json",
}

var jsonSchemaDocuments = map[SpecVersion]string{
	SpecVersion1_2: "schema/bom-1.2.schema.json",
	SpecVersion1_3: "schema/bom-1.3.schema.json",
	SpecVersion1_4: "schema/bom-1.4.schema.json",
	SpecVersion1_5: "schema/bom-1.5.schema.json",
	SpecVersion1_6: "schema/bom-1.6.schema.json",
	SpecVersion1_7: "schema/bom-1.7.schema.json",
}

// jsonSchemaCompanions are separate documents referenced by the main BOM
// schemas. They are preloaded so validation does not depend on network access,
// and so the jsf/schemax filename mismatch in published schema bundles cannot
// break an otherwise valid 1.0-1.7 document.
var jsonSchemaCompanions = []string{
	"schema/spdx.schema.json",
	"schema/jsf-0.82.schema.json",
	"schema/cryptography-defs.schema.json",
}

type jsonValidator struct{}

func newJSONValidator() validator {
	return &jsonValidator{}
}

func (jv jsonValidator) Validate(bom []byte, specVersion SpecVersion) error {
	_, ok := jsonSchemaFiles[specVersion]
	if !ok {
		return fmt.Errorf("no json schema known for spec version %s", specVersion)
	}
	schemaDocument := jsonSchemaDocuments[specVersion]

	mainSchema, err := jsonSchemaFS.ReadFile(schemaDocument)
	if err != nil {
		return fmt.Errorf("failed to validate: %w", err)
	}

	schemaLoader := gojsonschema.NewSchemaLoader()
	for _, companion := range jsonSchemaCompanions {
		companionSchema, err := jsonSchemaFS.ReadFile(companion)
		if err != nil {
			return fmt.Errorf("failed to validate: %w", err)
		}
		if err := schemaLoader.AddSchemas(gojsonschema.NewBytesLoader(companionSchema)); err != nil {
			return fmt.Errorf("failed to validate: %w", err)
		}
	}

	schema, err := schemaLoader.Compile(gojsonschema.NewBytesLoader(mainSchema))
	if err != nil {
		return fmt.Errorf("failed to validate: %w", err)
	}

	documentLoader := gojsonschema.NewBytesLoader(bom)

	result, err := schema.Validate(documentLoader)
	if err != nil {
		return fmt.Errorf("failed to validate: %w", err)
	}

	if result.Valid() {
		return nil
	}

	validationErrors := make(BOMValidationErrors, 0, len(result.Errors()))
	for _, validationError := range result.Errors() {
		validationErrors = append(validationErrors, BOMValidationError{
			Path:    validationError.Field(),
			Message: validationError.String(),
		})
	}

	return validationErrors
}
