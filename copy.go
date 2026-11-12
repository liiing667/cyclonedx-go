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
	"reflect"
)

// copy creates a deep copy of the BOM in a given destination.
//
// The copy is performed via reflection rather than an encode/decode round trip
// because gob omits zero values: a pointer to 0 or false would come back nil.
// Nil pointers and nil slices stay nil, and empty slices stay empty, so the
// copy serializes identically to the original.
func (b BOM) copy(dst *BOM) error {
	return deepCopy(reflect.ValueOf(dst).Elem(), reflect.ValueOf(b))
}

// deepCopy recursively copies src into dst, which must be settable and of the
// same type. It returns an error for kinds the BOM does not use today (maps,
// interfaces, channels, ...) so that adding such a field later fails loudly
// instead of producing a silently shallow copy.
func deepCopy(dst, src reflect.Value) error {
	if !dst.IsValid() || !src.IsValid() {
		return fmt.Errorf("deepCopy: invalid value")
	}
	if !dst.CanSet() {
		return fmt.Errorf("deepCopy: destination of type %s is not settable", dst.Type())
	}
	if dst.Type() != src.Type() {
		return fmt.Errorf("deepCopy: cannot copy %s to %s", src.Type(), dst.Type())
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

	case reflect.Bool, reflect.String,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
		reflect.Float32, reflect.Float64:
		dst.Set(src)

	default:
		return fmt.Errorf("deepCopy: unsupported kind %s", src.Kind())
	}

	return nil
}
