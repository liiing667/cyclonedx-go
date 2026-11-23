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
	"encoding/gob"
	"fmt"
	"reflect"
)

// copy creates a deep copy of the BOM in a given destination.
//
// The bulk of the BOM is copied with gob for compatibility with the historical
// copy behavior. Gob omits zero values, however, so it cannot preserve a
// pointer to zero (for example a vulnerability rating score of 0) or a pointer
// to an empty slice (for example an explicitly empty VEX response). The
// vulnerability slice is therefore kept out of the gob round trip and copied
// explicitly. That keeps VEX analysis and rating evidence attached to the
// exact vulnerability entry it belongs to.
func (b BOM) copy(dst *BOM) error {
	if dst == nil {
		return fmt.Errorf("cannot copy bom into nil destination")
	}

	// Keep the vulnerability slice out of the gob round trip. Gob cannot
	// preserve nil-versus-empty distinctions or pointers to zero values, so the
	// slice is copied explicitly below instead.
	vulnerabilities := b.Vulnerabilities
	b.Vulnerabilities = nil

	buf := bytes.Buffer{}
	if err := gob.NewEncoder(&buf).Encode(b); err != nil {
		return fmt.Errorf("failed to encode bom: %w", err)
	}
	if err := gob.NewDecoder(&buf).Decode(dst); err != nil {
		return fmt.Errorf("failed to decode bom: %w", err)
	}

	clonedVulnerabilities, err := cloneVulnerabilities(vulnerabilities)
	if err != nil {
		return fmt.Errorf("failed to copy vulnerabilities: %w", err)
	}
	dst.Vulnerabilities = clonedVulnerabilities

	return nil
}

// deepCopy recursively copies src into dst, which must be settable and of the
// same type. Unsupported kinds are rejected so that adding such a field later
// fails loudly instead of producing a shallow copy.
func deepCopy(dst, src reflect.Value) error {
	if !src.IsValid() {
		return fmt.Errorf("deepCopy: invalid source value")
	}
	if !dst.IsValid() {
		return fmt.Errorf("deepCopy: invalid destination value")
	}
	if dst.Type() != src.Type() {
		return fmt.Errorf("deepCopy: cannot copy %v to %v", src.Type(), dst.Type())
	}
	if !dst.CanSet() {
		return fmt.Errorf("deepCopy: destination of type %v is not settable", dst.Type())
	}

	switch src.Kind() {
	case reflect.Pointer:
		if src.IsNil() {
			dst.SetZero()
			return nil
		}
		pointer := reflect.New(src.Elem().Type())
		if err := deepCopy(pointer.Elem(), src.Elem()); err != nil {
			return err
		}
		dst.Set(pointer)

	case reflect.Interface:
		if src.IsNil() {
			dst.SetZero()
			return nil
		}
		value := reflect.New(src.Elem().Type()).Elem()
		if err := deepCopy(value, src.Elem()); err != nil {
			return err
		}
		dst.Set(value)

	case reflect.Struct:
		for index := 0; index < src.NumField(); index++ {
			if !dst.Field(index).CanSet() {
				return fmt.Errorf(
					"%s.%s: cannot set unexported field",
					src.Type().Name(),
					src.Type().Field(index).Name,
				)
			}
			if err := deepCopy(dst.Field(index), src.Field(index)); err != nil {
				return fmt.Errorf("%s.%s: %w", src.Type().Name(), src.Type().Field(index).Name, err)
			}
		}

	case reflect.Slice:
		if src.IsNil() {
			dst.SetZero()
			return nil
		}
		slice := reflect.MakeSlice(src.Type(), src.Len(), src.Len())
		for index := 0; index < src.Len(); index++ {
			if err := deepCopy(slice.Index(index), src.Index(index)); err != nil {
				return err
			}
		}
		dst.Set(slice)

	case reflect.Array:
		for index := 0; index < src.Len(); index++ {
			if err := deepCopy(dst.Index(index), src.Index(index)); err != nil {
				return err
			}
		}

	case reflect.Map:
		if src.IsNil() {
			dst.SetZero()
			return nil
		}
		mapping := reflect.MakeMapWithSize(src.Type(), src.Len())
		iterator := src.MapRange()
		for iterator.Next() {
			key := reflect.New(src.Type().Key()).Elem()
			if err := deepCopy(key, iterator.Key()); err != nil {
				return err
			}
			value := reflect.New(src.Type().Elem()).Elem()
			if err := deepCopy(value, iterator.Value()); err != nil {
				return err
			}
			mapping.SetMapIndex(key, value)
		}
		dst.Set(mapping)

	case reflect.Bool, reflect.String,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
		reflect.Float32, reflect.Float64,
		reflect.Complex64, reflect.Complex128:
		dst.Set(src)

	default:
		return fmt.Errorf("deepCopy: unsupported kind %v", src.Kind())
	}

	return nil
}
