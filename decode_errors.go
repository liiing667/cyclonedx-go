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
	"errors"
	"fmt"
)

var (
	// ErrDuplicateField indicates that a JSON object or XML element declares
	// the same field more than once. Duplicate fields are rejected because
	// decoders may otherwise silently keep an implementation-specific value.
	ErrDuplicateField = errors.New("duplicate field")

	// ErrInvalidBOMFormat indicates that the input does not declare the
	// CycloneDX BOM format.
	ErrInvalidBOMFormat = errors.New("invalid BOM format")
)

// ErrConflictingSpecVersion indicates that two format declarations name
// different CycloneDX specification versions. It also matches
// ErrInvalidSpecVersion, because a conflicting pair cannot identify one valid
// specification version.
var ErrConflictingSpecVersion = fmt.Errorf("%w: conflicting specification version", ErrInvalidSpecVersion)

// ErrConflictingXMLNamespace indicates that an XML document declares
// CycloneDX namespaces for more than one specification version.
var ErrConflictingXMLNamespace = fmt.Errorf("%w: conflicting XML namespace", ErrConflictingSpecVersion)

// ErrInvalidXMLNamespace indicates that an XML document's CycloneDX
// namespace cannot be mapped to a supported specification version.
var ErrInvalidXMLNamespace = fmt.Errorf("%w: invalid XML namespace", ErrInvalidSpecVersion)

// Aliases kept for callers that prefer a more specific or differently phrased
// category name. All aliases compare equal with errors.Is.
var (
	ErrDuplicateKey           = ErrDuplicateField
	ErrDuplicateJSONField     = ErrDuplicateField
	ErrDuplicateJSONKey       = ErrDuplicateField
	ErrDuplicateJSONObjectKey = ErrDuplicateField
	ErrDuplicateXMLField      = ErrDuplicateField
	ErrDuplicateXMLAttribute  = ErrDuplicateField
	ErrVersionConflict        = ErrConflictingSpecVersion
	ErrConflictingVersion     = ErrConflictingSpecVersion
	ErrSpecVersionConflict    = ErrConflictingSpecVersion
	ErrSpecVersionMismatch    = ErrConflictingSpecVersion
	ErrVersionMismatch        = ErrConflictingSpecVersion
	ErrFormatVersionConflict  = ErrConflictingSpecVersion
	ErrFormatVersionMismatch  = ErrConflictingSpecVersion
	ErrXMLNamespaceConflict   = ErrConflictingXMLNamespace
	ErrNamespaceConflict      = ErrConflictingXMLNamespace
	ErrNamespaceMismatch      = ErrConflictingXMLNamespace
	ErrXMLNamespaceMismatch   = ErrConflictingXMLNamespace
)

// categorizedDecodeError exposes one or more stable error categories while
// retaining a human-readable message with the offending location.
type categorizedDecodeError struct {
	message    string
	categories []error
}

func (e *categorizedDecodeError) Error() string {
	return e.message
}

func (e *categorizedDecodeError) Unwrap() []error {
	return e.categories
}

func newDecodeError(message string, categories ...error) error {
	nonNil := make([]error, 0, len(categories))
	for _, category := range categories {
		if category != nil {
			nonNil = append(nonNil, category)
		}
	}

	return &categorizedDecodeError{
		message:    message,
		categories: nonNil,
	}
}

func duplicateFieldError(field, location string, categories ...error) error {
	allCategories := make([]error, 0, len(categories)+1)
	allCategories = append(allCategories, ErrDuplicateField)
	allCategories = append(allCategories, categories...)

	return newDecodeError(
		fmt.Sprintf("duplicate field %q at %s", field, location),
		allCategories...,
	)
}

func conflictingSpecVersionError(format string, args ...any) error {
	return newDecodeError(
		fmt.Sprintf(format, args...),
		ErrConflictingSpecVersion,
	)
}
