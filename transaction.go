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
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"regexp"
)

// Transaction stages reported by BOMReport. They identify the last completed
// or failed step so a machine consumer can tell why a report is not clean.
const (
	BOMTransactionStageInput          = "input"
	BOMTransactionStageDecode         = "decode"
	BOMTransactionStageValidate       = "validate"
	BOMTransactionStageCopy           = "copy"
	BOMTransactionStageValidated      = "validated"
	BOMTransactionStageConvert        = "convert"
	BOMTransactionStageEncode         = "encode"
	BOMTransactionStageValidateOutput = "validate-output"
	BOMTransactionStageWrite          = "write"
	BOMTransactionStageEncoded        = "encoded"
)

var (
	// ErrBOMTransactionNotValidated indicates that a transaction's BOM was
	// requested before decode, schema validation and copy all succeeded.
	ErrBOMTransactionNotValidated = errors.New("bom transaction has not been validated")

	// ErrBOMUnsupportedSpecVersion indicates that an output version outside
	// the supported CycloneDX 1.0-1.7 range was requested.
	ErrBOMUnsupportedSpecVersion = errors.New("unsupported specification version")
)

// BOMValidationError is one schema violation found in a BOM document.
type BOMValidationError struct {
	Path    string `json:"path,omitempty"`
	Message string `json:"message"`
}

func (e BOMValidationError) Error() string {
	return e.Message
}

// BOMValidationErrors is a collection of schema violations. Its Error method
// retains the historical validator error text, while individual errors are
// available through Unwrap and Errors.
type BOMValidationErrors []BOMValidationError

func (errs BOMValidationErrors) Error() string {
	summary := fmt.Sprintf("encountered %d validation errors:", len(errs))
	for _, validationError := range errs {
		summary += fmt.Sprintf("\n  - %s", validationError.Message)
	}
	return summary
}

func (errs BOMValidationErrors) Unwrap() []error {
	unwrapped := make([]error, 0, len(errs))
	for index := range errs {
		unwrapped = append(unwrapped, &errs[index])
	}
	return unwrapped
}

// Errors returns a copy of the individual schema violations.
func (errs BOMValidationErrors) Errors() []BOMValidationError {
	return append([]BOMValidationError(nil), errs...)
}

// BOMReport is the machine-readable result of a BOM transaction. InputDigest,
// InputSpecVersion and ValidationErrors always refer to the transaction's
// frozen input. OutputDigest and OutputSpecVersion are only populated after an
// atomic encode and output validation succeeded. Clean is only true when every
// requested stage succeeded for that same input generation.
type BOMReport struct {
	InputDigest            string               `json:"inputDigest"`
	InputSize              int                  `json:"inputSize"`
	Format                 string               `json:"format"`
	InputSpecVersion       SpecVersion          `json:"inputSpecVersion,omitempty"`
	OutputSpecVersion      SpecVersion          `json:"outputSpecVersion,omitempty"`
	OutputDigest           string               `json:"outputDigest,omitempty"`
	OutputSize             int                  `json:"outputSize,omitempty"`
	Clean                  bool                 `json:"clean"`
	Copied                 bool                 `json:"copied"`
	Stage                  string               `json:"stage"`
	Message                string               `json:"message,omitempty"`
	ValidationErrors       []BOMValidationError `json:"validationErrors,omitempty"`
	OutputValidationErrors []BOMValidationError `json:"outputValidationErrors,omitempty"`
}

// Err returns nil for a clean report, otherwise an error carrying the message
// recorded by the failed stage.
func (r BOMReport) Err() error {
	if r.Clean {
		return nil
	}
	if r.Message != "" {
		return errors.New(r.Message)
	}
	return ErrBOMTransactionNotValidated
}

// BOMTransaction binds one frozen input document to its digest, schema
// validation errors, deep-copied BOM and final encode report. A failure in any
// stage leaves the transaction unvalidated or non-clean and never exposes a
// partial BOM or output.
type BOMTransaction struct {
	input       []byte
	inputDigest string
	format      BOMFileFormat

	report BOMReport

	validated bool
	copied    *BOM
	output    []byte
}

// NewBOMTransaction freezes input and computes the digest used by every
// subsequent stage. The caller can safely reuse or modify input afterwards.
func NewBOMTransaction(input []byte, format BOMFileFormat) *BOMTransaction {
	frozen := append([]byte(nil), input...)
	digest := sha256Hex(frozen)

	return &BOMTransaction{
		input:       frozen,
		inputDigest: digest,
		format:      format,
		report: BOMReport{
			InputDigest: digest,
			InputSize:   len(frozen),
			Format:      format.String(),
			Stage:       BOMTransactionStageInput,
		},
	}
}

// Digest returns the SHA-256 digest of the frozen input document.
func (t *BOMTransaction) Digest() string {
	if t == nil {
		return ""
	}
	return t.inputDigest
}

// Input returns a copy of the frozen input document.
func (t *BOMTransaction) Input() []byte {
	if t == nil {
		return nil
	}
	return append([]byte(nil), t.input...)
}

// Report returns a snapshot of the current transaction report.
func (t *BOMTransaction) Report() BOMReport {
	if t == nil {
		return BOMReport{}
	}

	report := t.report
	report.ValidationErrors = append([]BOMValidationError(nil), t.report.ValidationErrors...)
	report.OutputValidationErrors = append(
		[]BOMValidationError(nil),
		t.report.OutputValidationErrors...,
	)
	return report
}

// Validated reports whether decode, schema validation and copy all succeeded.
func (t *BOMTransaction) Validated() bool {
	return t != nil && t.validated
}

// Output returns a copy of the last successfully encoded output.
func (t *BOMTransaction) Output() []byte {
	if t == nil {
		return nil
	}
	return append([]byte(nil), t.output...)
}

// Validate decodes the frozen input, validates it against the schema for its
// declared specification version and produces a deep copy. On failure the
// transaction remains unvalidated: no decoded BOM, copy or output is exposed.
func (t *BOMTransaction) Validate() error {
	if t == nil {
		return fmt.Errorf("cannot validate a nil BOM transaction")
	}

	t.resetValidation()

	t.report.Stage = BOMTransactionStageDecode
	var decoded BOM
	if err := NewBOMDecoder(bytes.NewReader(t.input), t.format).Decode(&decoded); err != nil {
		t.report.Message = err.Error()
		return err
	}
	t.report.InputSpecVersion = decoded.SpecVersion

	t.report.Stage = BOMTransactionStageValidate
	if err := validateDeclaredVersion(t.input, t.format, decoded.SpecVersion); err != nil {
		t.report.Message = err.Error()
		t.report.ValidationErrors = collectValidationErrors(err)
		return err
	}
	if err := NewBOMValidator(t.format).Validate(t.input, decoded.SpecVersion); err != nil {
		t.report.Message = err.Error()
		t.report.ValidationErrors = collectValidationErrors(err)
		return err
	}

	t.report.Stage = BOMTransactionStageCopy
	var copied BOM
	if err := decoded.copy(&copied); err != nil {
		err = fmt.Errorf("failed to copy bom: %w", err)
		t.report.Message = err.Error()
		return err
	}

	t.copied = &copied
	t.validated = true
	t.report.Copied = true
	t.report.Clean = true
	t.report.Stage = BOMTransactionStageValidated
	return nil
}

// Copy returns a deep copy of the validated BOM. It never returns the
// transaction's internal copy, so callers cannot mutate later stages.
func (t *BOMTransaction) Copy() (*BOM, error) {
	if t == nil || !t.validated || t.copied == nil {
		return nil, ErrBOMTransactionNotValidated
	}

	copied, err := t.copied.Copy()
	if err != nil {
		t.report.Clean = false
		t.report.Stage = BOMTransactionStageCopy
		t.report.Message = err.Error()
		return nil, err
	}
	return copied, nil
}

// Encode converts the validated copy to specVersion and writes it atomically.
// Nothing is written to writer unless conversion and encoding both succeeded.
// A failed encode resets Clean and the output fields, but keeps the validated
// copy intact so the encode can be retried without re-reading the input.
func (t *BOMTransaction) Encode(writer io.Writer, specVersion SpecVersion) error {
	if t == nil || !t.validated || t.copied == nil {
		return ErrBOMTransactionNotValidated
	}

	t.output = nil
	t.report.Clean = false
	t.report.OutputDigest = ""
	t.report.OutputSize = 0
	t.report.OutputSpecVersion = 0
	t.report.OutputValidationErrors = nil
	t.report.Message = ""
	t.report.Stage = BOMTransactionStageConvert

	if writer == nil {
		err := fmt.Errorf("cannot encode to a nil writer")
		t.report.Stage = BOMTransactionStageWrite
		t.report.Message = err.Error()
		return err
	}

	if specVersion < SpecVersion1_0 || specVersion > SpecVersion1_7 {
		err := fmt.Errorf("%w: %s", ErrBOMUnsupportedSpecVersion, specVersion)
		t.report.Message = err.Error()
		return err
	}

	converted, err := t.copied.copyAndConvert(specVersion)
	if err != nil {
		t.report.Message = err.Error()
		return err
	}

	t.report.Stage = BOMTransactionStageEncode
	var buffer bytes.Buffer
	if err := NewBOMEncoder(&buffer, t.format).Encode(converted); err != nil {
		t.report.Message = err.Error()
		return err
	}

	t.report.Stage = BOMTransactionStageValidateOutput
	var decodedOutput BOM
	if err := NewBOMDecoder(bytes.NewReader(buffer.Bytes()), t.format).Decode(&decodedOutput); err != nil {
		err = fmt.Errorf("failed to decode encoded bom: %w", err)
		t.report.Message = err.Error()
		return err
	}
	if decodedOutput.SpecVersion != specVersion {
		err := fmt.Errorf(
			"encoded bom declares specification version %s, expected %s",
			decodedOutput.SpecVersion,
			specVersion,
		)
		t.report.Message = err.Error()
		return err
	}
	if err := validateDeclaredVersion(buffer.Bytes(), t.format, specVersion); err != nil {
		t.report.Message = err.Error()
		t.report.OutputValidationErrors = collectValidationErrors(err)
		return err
	}
	if err := NewBOMValidator(t.format).Validate(buffer.Bytes(), specVersion); err != nil {
		t.report.Message = err.Error()
		t.report.OutputValidationErrors = collectValidationErrors(err)
		return err
	}

	t.report.Stage = BOMTransactionStageWrite
	if err := writeAll(writer, buffer.Bytes()); err != nil {
		t.report.Message = err.Error()
		return err
	}

	t.output = append([]byte(nil), buffer.Bytes()...)
	t.report.OutputDigest = sha256Hex(t.output)
	t.report.OutputSize = len(t.output)
	t.report.OutputSpecVersion = specVersion
	t.report.Clean = true
	t.report.Stage = BOMTransactionStageEncoded
	return nil
}

func (t *BOMTransaction) resetValidation() {
	t.validated = false
	t.copied = nil
	t.output = nil
	t.report = BOMReport{
		InputDigest: t.inputDigest,
		InputSize:   len(t.input),
		Format:      t.format.String(),
		Stage:       BOMTransactionStageInput,
	}
}

// DecodeValidatedBOM decodes and schema-validates input and returns a deep copy
// only when every step succeeded. On failure both the BOM and copy are nil and
// the report records the failing stage and validation errors.
func DecodeValidatedBOM(input []byte, format BOMFileFormat) (*BOM, *BOMReport, error) {
	transaction := NewBOMTransaction(input, format)
	if err := transaction.Validate(); err != nil {
		report := transaction.Report()
		return nil, &report, err
	}

	bom, err := transaction.Copy()
	report := transaction.Report()
	if err != nil {
		return nil, &report, err
	}

	return bom, &report, nil
}

// ValidateBOM decodes and schema-validates input and returns the machine
// report for that input generation.
func ValidateBOM(input []byte, format BOMFileFormat) (*BOMReport, error) {
	transaction := NewBOMTransaction(input, format)
	err := transaction.Validate()
	report := transaction.Report()
	return &report, err
}

// ValidateBOMObject serializes bom with format and validates the resulting
// document. The report is tied to the serialized representation, including
// its digest, so an invalid in-memory BOM can never produce a clean report.
func ValidateBOMObject(bom *BOM, format BOMFileFormat) (*BOMReport, error) {
	if bom == nil {
		err := fmt.Errorf("cannot validate a nil BOM")
		report := BOMReport{
			Format:  format.String(),
			Stage:   BOMTransactionStageEncode,
			Message: err.Error(),
		}
		return &report, err
	}

	var buffer bytes.Buffer
	if err := NewBOMEncoder(&buffer, format).Encode(bom); err != nil {
		report := BOMReport{
			Format:  format.String(),
			Stage:   BOMTransactionStageEncode,
			Message: err.Error(),
		}
		return &report, err
	}

	return ValidateBOM(buffer.Bytes(), format)
}

// EncodeValidatedBOM validates input and atomically encodes a converted copy
// to specVersion. The returned report always describes the frozen input and
// the requested output version, or the stage that failed.
func EncodeValidatedBOM(
	writer io.Writer,
	input []byte,
	format BOMFileFormat,
	specVersion SpecVersion,
) (*BOMReport, error) {
	transaction := NewBOMTransaction(input, format)
	if err := transaction.Validate(); err != nil {
		report := transaction.Report()
		return &report, err
	}

	err := transaction.Encode(writer, specVersion)
	report := transaction.Report()
	return &report, err
}

func collectValidationErrors(err error) []BOMValidationError {
	var validationErrors BOMValidationErrors
	if errors.As(err, &validationErrors) {
		return validationErrors.Errors()
	}

	var validationError *BOMValidationError
	if errors.As(err, &validationError) {
		return []BOMValidationError{*validationError}
	}

	return []BOMValidationError{{Message: err.Error()}}
}

var jsonSchemaVersionRegexp = regexp.MustCompile(`bom-([0-9]+\.[0-9]+)(?:-strict)?\.schema\.json`)
var xmlSchemaLocationVersionRegexp = regexp.MustCompile(`bom[-/]([0-9]+\.[0-9]+)\.xsd`)

// validateDeclaredVersion makes the report's InputSpecVersion match every
// version declaration present in the document. Without this check a BOM that
// declares 1.6 in $schema and 1.7 in specVersion could be validated as 1.7
// and published as clean under the wrong version.
func validateDeclaredVersion(input []byte, format BOMFileFormat, specVersion SpecVersion) error {
	switch format {
	case BOMFileFormatJSON:
		return validateJSONDeclaredVersion(input, specVersion)
	case BOMFileFormatXML:
		return validateXMLDeclaredVersion(input, specVersion)
	default:
		return nil
	}
}

func validateJSONDeclaredVersion(input []byte, specVersion SpecVersion) error {
	var header struct {
		JSONSchema string `json:"$schema"`
	}
	if err := json.Unmarshal(input, &header); err != nil {
		return err
	}
	if header.JSONSchema == "" {
		return nil
	}

	schemaVersion, ok := specVersionFromJSONSchema(header.JSONSchema)
	if !ok {
		if jsonSchemaVersionRegexp.MatchString(header.JSONSchema) {
			return fmt.Errorf(
				"conflicting specification version: $schema declares an unsupported version %q, specVersion declares %s",
				header.JSONSchema,
				specVersion,
			)
		}
		return nil
	}
	if schemaVersion != specVersion {
		return fmt.Errorf(
			"conflicting specification version: $schema declares %s, specVersion declares %s",
			schemaVersion,
			specVersion,
		)
	}

	return nil
}

func validateXMLDeclaredVersion(input []byte, specVersion SpecVersion) error {
	const xmlSchemaInstanceNamespace = "http://www.w3.org/2001/XMLSchema-instance"

	decoder := xml.NewDecoder(bytes.NewReader(input))
	for {
		token, err := decoder.Token()
		if err != nil {
			return nil
		}

		start, ok := token.(xml.StartElement)
		if !ok {
			continue
		}

		for _, attribute := range start.Attr {
			if attribute.Name.Space != xmlSchemaInstanceNamespace ||
				attribute.Name.Local != "schemaLocation" {
				continue
			}

			for _, match := range xmlSchemaLocationVersionRegexp.FindAllStringSubmatch(attribute.Value, -1) {
				if len(match) != 2 {
					continue
				}
				if _, ok := transactionSpecVersionFromString(match[1]); !ok {
					return fmt.Errorf(
						"conflicting specification version: XML namespace declares %s, xsi:schemaLocation declares unsupported version %s",
						specVersion,
						match[1],
					)
				}
			}

			for _, declaredVersion := range specVersionsFromXMLSchemaLocation(attribute.Value) {
				if declaredVersion != specVersion {
					return fmt.Errorf(
						"conflicting specification version: XML namespace declares %s, xsi:schemaLocation declares %s",
						specVersion,
						declaredVersion,
					)
				}
			}
		}

		return nil
	}
}

func specVersionsFromXMLSchemaLocation(schemaLocation string) []SpecVersion {
	matches := xmlSchemaLocationVersionRegexp.FindAllStringSubmatch(schemaLocation, -1)
	versions := make([]SpecVersion, 0, len(matches))
	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		for version := SpecVersion1_0; version <= SpecVersion1_7; version++ {
			if version.String() == match[1] {
				versions = append(versions, version)
				break
			}
		}
	}
	return versions
}

func specVersionFromJSONSchema(schema string) (SpecVersion, bool) {
	match := jsonSchemaVersionRegexp.FindStringSubmatch(schema)
	if len(match) != 2 {
		return 0, false
	}

	return transactionSpecVersionFromString(match[1])
}

func transactionSpecVersionFromString(declared string) (SpecVersion, bool) {
	for candidate := SpecVersion1_0; candidate <= SpecVersion1_7; candidate++ {
		if candidate.String() == declared {
			return candidate, true
		}
	}

	return 0, false
}

func sha256Hex(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

// String returns the wire name of a BOM file format.
func (f BOMFileFormat) String() string {
	switch f {
	case BOMFileFormatJSON:
		return "json"
	case BOMFileFormatXML:
		return "xml"
	default:
		return fmt.Sprintf("BOMFileFormat(%d)", int(f))
	}
}
