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
//
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) OWASP Foundation. All Rights Reserved.

package cyclonedx

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"regexp"
)

const xmlSchemaInstanceNamespace = "http://www.w3.org/2001/XMLSchema-instance"

var (
	jsonSchemaVersionPattern       = regexp.MustCompile(`bom-([0-9]+\.[0-9]+)(?:-strict)?\.schema\.json(?:[?#].*)?$`)
	xmlNamespacePattern            = regexp.MustCompile(`^https?://cyclonedx\.org/schema/bom/`)
	xmlSchemaLocationVersionRegexp = regexp.MustCompile(`bom[-/]([0-9]+\.[0-9]+)`)
)

type jsonBOMHeader struct {
	JSONSchema  *string      `json:"$schema"`
	BOMFormat   *string      `json:"bomFormat"`
	SpecVersion *SpecVersion `json:"specVersion"`
}

type xmlBOMHeader struct {
	namespace   string
	specVersion SpecVersion
}

func validateJSONDocument(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()

	if err := validateJSONValue(decoder, "$"); err != nil {
		return err
	}

	token, err := decoder.Token()
	if err == io.EOF {
		return nil
	}
	if err != nil {
		return err
	}

	return fmt.Errorf("unexpected trailing JSON value %v", token)
}

func validateJSONValue(decoder *json.Decoder, path string) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}

	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}

	switch delim {
	case '{':
		names := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}

			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("invalid JSON object key at %s", path)
			}

			if _, duplicate := names[key]; duplicate {
				var categories []error
				if path == "$" && (key == "$schema" || key == "specVersion" || key == "bomFormat") {
					categories = append(categories, ErrConflictingSpecVersion)
				}
				return duplicateFieldError(key, path+"."+key, categories...)
			}
			names[key] = struct{}{}

			if err := validateJSONValue(decoder, path+"."+key); err != nil {
				return err
			}
		}

		closingToken, err := decoder.Token()
		if err != nil {
			return err
		}
		if closingToken != json.Delim('}') {
			return fmt.Errorf("invalid JSON object at %s", path)
		}

	case '[':
		index := 0
		for decoder.More() {
			if err := validateJSONValue(decoder, fmt.Sprintf("%s[%d]", path, index)); err != nil {
				return err
			}
			index++
		}

		closingToken, err := decoder.Token()
		if err != nil {
			return err
		}
		if closingToken != json.Delim(']') {
			return fmt.Errorf("invalid JSON array at %s", path)
		}

	default:
		return fmt.Errorf("unexpected JSON delimiter %q at %s", delim, path)
	}

	return nil
}

func validateJSONVersion(data []byte) error {
	var header jsonBOMHeader
	if err := json.Unmarshal(data, &header); err != nil {
		return err
	}

	if header.BOMFormat == nil || *header.BOMFormat == "" {
		return newDecodeError("missing bomFormat declaration", ErrInvalidBOMFormat)
	}
	if *header.BOMFormat != BOMFormat {
		return newDecodeError(
			fmt.Sprintf("invalid bomFormat %q, expected %q", *header.BOMFormat, BOMFormat),
			ErrInvalidBOMFormat,
		)
	}

	if header.SpecVersion == nil {
		return newDecodeError("missing specVersion declaration", ErrConflictingSpecVersion, ErrInvalidSpecVersion)
	}

	if header.JSONSchema == nil || *header.JSONSchema == "" {
		return nil
	}

	schemaVersion, ok := specVersionFromJSONSchema(*header.JSONSchema)
	if !ok {
		return newDecodeError(
			fmt.Sprintf("cannot determine specification version from $schema %q", *header.JSONSchema),
			ErrInvalidSpecVersion,
			ErrConflictingSpecVersion,
		)
	}

	if schemaVersion != *header.SpecVersion {
		return conflictingSpecVersionError(
			"conflicting specification version: $schema declares %s, specVersion declares %s",
			schemaVersion,
			*header.SpecVersion,
		)
	}

	return nil
}

func specVersionFromJSONSchema(schema string) (SpecVersion, bool) {
	match := jsonSchemaVersionPattern.FindStringSubmatch(schema)
	if len(match) != 2 {
		return 0, false
	}
	return specVersionFromString(match[1])
}

func specVersionFromString(version string) (SpecVersion, bool) {
	for candidate := SpecVersion1_0; candidate <= SpecVersion1_7; candidate++ {
		if candidate.String() == version {
			return candidate, true
		}
	}
	return 0, false
}

func specVersionFromXMLNamespace(namespace string) (SpecVersion, bool) {
	for candidate, candidateNamespace := range xmlNamespaces {
		if candidateNamespace == namespace {
			return candidate, true
		}
	}
	return 0, false
}

func looksLikeCycloneDXXMLNamespace(namespace string) bool {
	return xmlNamespacePattern.MatchString(namespace)
}

func specVersionsFromXMLSchemaLocation(schemaLocation string) []SpecVersion {
	matches := xmlSchemaLocationVersionRegexp.FindAllStringSubmatch(schemaLocation, -1)
	versions := make([]SpecVersion, 0, len(matches))
	for _, match := range matches {
		if version, ok := specVersionFromString(match[1]); ok {
			versions = append(versions, version)
		}
	}
	return versions
}

func validateXMLDocument(data []byte) (xmlBOMHeader, error) {
	decoder := xml.NewDecoder(bytes.NewReader(data))

	var header xmlBOMHeader
	depth := 0
	rootSeen := false

	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return header, err
		}

		switch typedToken := token.(type) {
		case xml.StartElement:
			if err := validateXMLAttributes(typedToken); err != nil {
				return header, err
			}

			if depth == 0 {
				if rootSeen {
					return header, newDecodeError("multiple XML root elements", ErrInvalidBOMFormat)
				}
				rootSeen = true

				if typedToken.Name.Local != "bom" {
					return header, newDecodeError(
						fmt.Sprintf("invalid XML root element %q, expected \"bom\"", typedToken.Name.Local),
						ErrInvalidBOMFormat,
					)
				}

				header.namespace = typedToken.Name.Space
				specVersion, ok := specVersionFromXMLNamespace(header.namespace)
				if !ok {
					categories := []error{ErrInvalidXMLNamespace, ErrInvalidSpecVersion}
					if looksLikeCycloneDXXMLNamespace(header.namespace) {
						categories = append(
							categories,
							ErrConflictingSpecVersion,
							ErrConflictingXMLNamespace,
						)
					}
					return header, newDecodeError(
						fmt.Sprintf("unsupported CycloneDX XML namespace %q", header.namespace),
						categories...,
					)
				}
				header.specVersion = specVersion
			}

			if err := validateXMLNamespaceDeclarations(typedToken, depth, header.specVersion); err != nil {
				return header, err
			}
			if depth == 0 {
				if err := validateXMLSchemaLocation(typedToken, header.specVersion); err != nil {
					return header, err
				}
			}

			depth++

		case xml.EndElement:
			depth--
			if depth < 0 {
				return header, newDecodeError("unexpected XML end element", ErrInvalidBOMFormat)
			}

		case xml.CharData:
			if depth == 0 && len(bytes.TrimSpace(typedToken)) > 0 {
				return header, newDecodeError("unexpected text outside XML root element", ErrInvalidBOMFormat)
			}
		}
	}

	if !rootSeen {
		return header, newDecodeError("missing XML root element", ErrInvalidBOMFormat)
	}
	if depth != 0 {
		return header, newDecodeError("unclosed XML element", ErrInvalidBOMFormat)
	}

	return header, nil
}

func validateXMLAttributes(start xml.StartElement) error {
	attributes := make(map[xml.Name]struct{}, len(start.Attr))
	for _, attribute := range start.Attr {
		if _, duplicate := attributes[attribute.Name]; duplicate {
			var categories []error
			if attribute.Name.Local == "xmlns" {
				categories = append(categories, ErrConflictingXMLNamespace, ErrConflictingSpecVersion)
			}

			return duplicateFieldError(
				xmlAttributeName(attribute.Name),
				fmt.Sprintf("XML element <%s>", start.Name.Local),
				categories...,
			)
		}
		attributes[attribute.Name] = struct{}{}
	}

	return nil
}

func validateXMLNamespaceDeclarations(start xml.StartElement, depth int, rootSpecVersion SpecVersion) error {
	for _, attribute := range start.Attr {
		if !isNamespaceDeclaration(attribute.Name) {
			continue
		}

		namespace := attribute.Value
		declaredVersion, ok := specVersionFromXMLNamespace(namespace)
		if !ok {
			if looksLikeCycloneDXXMLNamespace(namespace) {
				return newDecodeError(
					fmt.Sprintf("unsupported CycloneDX XML namespace %q", namespace),
					ErrInvalidXMLNamespace,
					ErrInvalidSpecVersion,
					ErrConflictingXMLNamespace,
				)
			}
			continue
		}

		if depth == 0 && declaredVersion != rootSpecVersion {
			return conflictingNamespaceError(
				"conflicting XML namespace: root element uses %q, but declares %q",
				xmlNamespaces[rootSpecVersion],
				namespace,
			)
		}
		if depth > 0 && declaredVersion != rootSpecVersion {
			return conflictingNamespaceError(
				"conflicting XML namespace: nested element <%s> declares %q, but root element uses %q",
				start.Name.Local,
				namespace,
				xmlNamespaces[rootSpecVersion],
			)
		}
	}

	return nil
}

func validateXMLSchemaLocation(start xml.StartElement, rootSpecVersion SpecVersion) error {
	for _, attribute := range start.Attr {
		if attribute.Name.Space != xmlSchemaInstanceNamespace || attribute.Name.Local != "schemaLocation" {
			continue
		}

		for _, declaredVersion := range specVersionsFromXMLSchemaLocation(attribute.Value) {
			if declaredVersion != rootSpecVersion {
				return conflictingNamespaceError(
					"conflicting XML namespace: root element uses %q, but xsi:schemaLocation declares %q",
					xmlNamespaces[rootSpecVersion],
					attribute.Value,
				)
			}
		}
	}

	return nil
}

func conflictingNamespaceError(format string, args ...any) error {
	return newDecodeError(
		fmt.Sprintf(format, args...),
		ErrConflictingXMLNamespace,
		ErrConflictingSpecVersion,
	)
}

func isNamespaceDeclaration(name xml.Name) bool {
	return name.Local == "xmlns" || name.Space == "xmlns"
}

func xmlAttributeName(name xml.Name) string {
	if name.Space == "xmlns" {
		return "xmlns:" + name.Local
	}
	if name.Local == "xmlns" {
		return "xmlns"
	}
	if name.Space == "" {
		return name.Local
	}
	return name.Space + ":" + name.Local
}
