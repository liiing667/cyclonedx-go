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
	// ErrDuplicateBOMRef indicates that more than one BOM object declares the
	// same non-empty bom-ref.
	ErrDuplicateBOMRef = errors.New("duplicate bom-ref")

	// ErrDanglingBOMRef indicates that a dependency or composition references
	// a bom-ref that is not declared in the BOM.
	ErrDanglingBOMRef = errors.New("dangling bom-ref")

	// Aliases for callers that use a different spelling for the same
	// conditions. All aliases compare equal with errors.Is.
	ErrDuplicateBOMReference = ErrDuplicateBOMRef
	ErrDuplicateBOMRefs      = ErrDuplicateBOMRef
	ErrDuplicateBomRef       = ErrDuplicateBOMRef
	ErrDuplicateReference    = ErrDuplicateBOMRef
	ErrBOMRefConflict        = ErrDuplicateBOMRef
	ErrAmbiguousBOMRef       = ErrDuplicateBOMRef

	ErrDanglingBOMReference = ErrDanglingBOMRef
	ErrDanglingBOMRefs      = ErrDanglingBOMRef
	ErrDanglingBomRef       = ErrDanglingBOMRef
	ErrUnknownBOMRef        = ErrDanglingBOMRef
	ErrUnresolvedBOMRef     = ErrDanglingBOMRef
)

type bomRefIdentity struct {
	kind     string
	location string
}

type bomRefUse struct {
	ref      string
	kind     string
	location string
}

type bomRefValidator struct {
	identities      map[string]bomRefIdentity
	allRefs         map[string]struct{}
	workloadRefs    map[string]struct{}
	dependencyNodes map[string]string
	dependencyUses  []bomRefUse
	compositionUses []bomRefUse
	hasWorkloads    bool
}

func newBOMRefValidator() *bomRefValidator {
	return &bomRefValidator{
		identities:      make(map[string]bomRefIdentity),
		allRefs:         make(map[string]struct{}),
		workloadRefs:    make(map[string]struct{}),
		dependencyNodes: make(map[string]string),
	}
}

// ValidateBOMReferences checks that component, dependency and composition
// identities are unique and that their references resolve within the BOM.
func ValidateBOMReferences(bom *BOM) error {
	return validateBOMReferences(bom)
}

// ValidateBOMRefs is an alias for ValidateBOMReferences.
func ValidateBOMRefs(bom *BOM) error {
	return validateBOMReferences(bom)
}

// Validate checks that component, dependency and composition identities are
// unique and that their references resolve within the BOM.
func (b *BOM) Validate() error {
	return validateBOMReferences(b)
}

func validateBOMReferences(bom *BOM) error {
	if bom == nil {
		return fmt.Errorf("cannot validate a nil BOM")
	}

	validator := newBOMRefValidator()

	if bom.Metadata != nil {
		if err := validator.addComponentTree(bom.Metadata.Component, "metadata.component"); err != nil {
			return err
		}
		if bom.Metadata.Tools != nil {
			if err := validator.addComponentList(
				bom.Metadata.Tools.Components,
				"metadata.tools.components",
			); err != nil {
				return err
			}
			if err := validator.addServiceList(
				bom.Metadata.Tools.Services,
				"metadata.tools.services",
			); err != nil {
				return err
			}
		}
	}

	if bom.Components != nil {
		if err := validator.addComponentList(bom.Components, "components"); err != nil {
			return err
		}
	}

	if bom.Services != nil {
		if err := validator.addServiceList(bom.Services, "services"); err != nil {
			return err
		}
	}

	if bom.Vulnerabilities != nil {
		for i := range *bom.Vulnerabilities {
			if err := validator.addIdentity(
				(*bom.Vulnerabilities)[i].BOMRef,
				"vulnerability",
				fmt.Sprintf("vulnerabilities[%d]", i),
			); err != nil {
				return err
			}
		}
	}

	if bom.Compositions != nil {
		for i := range *bom.Compositions {
			if err := validator.addComposition(
				&(*bom.Compositions)[i],
				fmt.Sprintf("compositions[%d]", i),
			); err != nil {
				return err
			}
		}
	}

	if bom.Dependencies != nil {
		for i := range *bom.Dependencies {
			if err := validator.addDependency(
				&(*bom.Dependencies)[i],
				fmt.Sprintf("dependencies[%d]", i),
			); err != nil {
				return err
			}
		}
	}

	return validator.validateUses()
}

func (v *bomRefValidator) addIdentity(ref, kind, location string) error {
	if ref == "" {
		return nil
	}

	current := bomRefIdentity{kind: kind, location: location}
	if previous, exists := v.identities[ref]; exists {
		return duplicateBOMRefError(ref, previous, current)
	}

	v.identities[ref] = current
	v.allRefs[ref] = struct{}{}
	return nil
}

func (v *bomRefValidator) addWorkloadRef(ref, kind, location string) error {
	if err := v.addIdentity(ref, kind, location); err != nil {
		return err
	}
	if ref != "" {
		v.workloadRefs[ref] = struct{}{}
	}
	return nil
}

func (v *bomRefValidator) addResolvableAlias(ref string) {
	if ref == "" {
		return
	}

	v.allRefs[ref] = struct{}{}
	v.workloadRefs[ref] = struct{}{}
}

func (v *bomRefValidator) addComponentList(components *[]Component, location string) error {
	if components == nil {
		return nil
	}

	for i := range *components {
		if err := v.addComponentTree(
			&(*components)[i],
			fmt.Sprintf("%s[%d]", location, i),
		); err != nil {
			return err
		}
	}
	return nil
}

func (v *bomRefValidator) addComponentTree(component *Component, location string) error {
	if component == nil {
		return nil
	}
	v.hasWorkloads = true

	if err := v.addWorkloadRef(component.BOMRef, "component", location); err != nil {
		return err
	}

	// Some producers use the purl as the dependency reference even when the
	// optional bom-ref is omitted. Legacy programmatic BOMs may also use the
	// component name when neither a bom-ref nor a purl exists. Keep accepting
	// those documents while still treating actual bom-ref declarations as
	// identities.
	if component.PackageURL != "" {
		v.addResolvableAlias(component.PackageURL)
	} else if component.BOMRef == "" {
		v.addResolvableAlias(component.Name)
	}

	if component.Components != nil {
		if err := v.addComponentList(component.Components, location+".components"); err != nil {
			return err
		}
	}

	if component.Pedigree != nil {
		if err := v.addComponentList(component.Pedigree.Ancestors, location+".pedigree.ancestors"); err != nil {
			return err
		}
		if err := v.addComponentList(component.Pedigree.Descendants, location+".pedigree.descendants"); err != nil {
			return err
		}
		if err := v.addComponentList(component.Pedigree.Variants, location+".pedigree.variants"); err != nil {
			return err
		}
	}

	return nil
}

func (v *bomRefValidator) addServiceList(services *[]Service, location string) error {
	if services == nil {
		return nil
	}

	for i := range *services {
		if err := v.addServiceTree(
			&(*services)[i],
			fmt.Sprintf("%s[%d]", location, i),
		); err != nil {
			return err
		}
	}
	return nil
}

func (v *bomRefValidator) addServiceTree(service *Service, location string) error {
	if service == nil {
		return nil
	}
	v.hasWorkloads = true

	if err := v.addWorkloadRef(service.BOMRef, "service", location); err != nil {
		return err
	}
	if service.BOMRef == "" {
		v.addResolvableAlias(service.Name)
	}

	return v.addServiceList(service.Services, location+".services")
}

func (v *bomRefValidator) addDependency(dependency *Dependency, location string) error {
	if dependency == nil {
		return nil
	}

	if dependency.Ref != "" {
		refLocation := location + ".ref"
		if previous, exists := v.dependencyNodes[dependency.Ref]; exists {
			return duplicateBOMRefError(
				dependency.Ref,
				bomRefIdentity{kind: "dependency", location: previous},
				bomRefIdentity{kind: "dependency", location: refLocation},
			)
		}
		v.dependencyNodes[dependency.Ref] = refLocation
		v.dependencyUses = append(v.dependencyUses, bomRefUse{
			ref:      dependency.Ref,
			kind:     "dependency",
			location: refLocation,
		})
	}

	if err := v.addDependencyRefList(dependency.Dependencies, "dependency", location+".dependsOn"); err != nil {
		return err
	}
	if err := v.addDependencyRefList(dependency.Provides, "dependency", location+".provides"); err != nil {
		return err
	}

	return nil
}

func (v *bomRefValidator) addDependencyRefList(refs *[]string, kind, location string) error {
	if refs == nil {
		return nil
	}

	seen := make(map[string]string, len(*refs))
	for i := range *refs {
		ref := (*refs)[i]
		if ref == "" {
			continue
		}

		refLocation := fmt.Sprintf("%s[%d]", location, i)
		if previous, exists := seen[ref]; exists {
			return duplicateBOMRefError(
				ref,
				bomRefIdentity{kind: kind, location: previous},
				bomRefIdentity{kind: kind, location: refLocation},
			)
		}
		seen[ref] = refLocation
		v.dependencyUses = append(v.dependencyUses, bomRefUse{
			ref:      ref,
			kind:     kind,
			location: refLocation,
		})
	}

	return nil
}

func (v *bomRefValidator) addComposition(composition *Composition, location string) error {
	if composition == nil {
		return nil
	}

	if err := v.addIdentity(composition.BOMRef, "composition", location); err != nil {
		return err
	}

	if err := v.addCompositionRefList(composition.Assemblies, "composition", location+".assemblies"); err != nil {
		return err
	}
	if err := v.addCompositionRefList(composition.Dependencies, "composition", location+".dependencies"); err != nil {
		return err
	}
	if err := v.addCompositionRefList(composition.Vulnerabilities, "composition", location+".vulnerabilities"); err != nil {
		return err
	}

	return nil
}

func (v *bomRefValidator) addCompositionRefList(refs *[]BOMReference, kind, location string) error {
	if refs == nil {
		return nil
	}

	seen := make(map[string]string, len(*refs))
	for i := range *refs {
		ref := string((*refs)[i])
		if ref == "" {
			continue
		}

		refLocation := fmt.Sprintf("%s[%d]", location, i)
		if previous, exists := seen[ref]; exists {
			return duplicateBOMRefError(
				ref,
				bomRefIdentity{kind: kind, location: previous},
				bomRefIdentity{kind: kind, location: refLocation},
			)
		}
		seen[ref] = refLocation
		v.compositionUses = append(v.compositionUses, bomRefUse{
			ref:      ref,
			kind:     kind,
			location: refLocation,
		})
	}

	return nil
}

func (v *bomRefValidator) validateUses() error {
	if v.hasWorkloads {
		for _, use := range v.dependencyUses {
			if _, resolves := v.workloadRefs[use.ref]; resolves {
				continue
			}
			if IsBOMLink(use.ref) {
				continue
			}
			return danglingBOMRefError(use)
		}
	}

	for _, use := range v.compositionUses {
		if _, resolves := v.allRefs[use.ref]; resolves {
			continue
		}
		if IsBOMLink(use.ref) {
			continue
		}
		return danglingBOMRefError(use)
	}

	return nil
}

func duplicateBOMRefError(ref string, previous, current bomRefIdentity) error {
	return fmt.Errorf(
		"%w %q: %s at %s conflicts with %s at %s",
		ErrDuplicateBOMRef,
		ref,
		previous.kind,
		previous.location,
		current.kind,
		current.location,
	)
}

func danglingBOMRefError(use bomRefUse) error {
	return fmt.Errorf(
		"%w %q: %s at %s",
		ErrDanglingBOMRef,
		use.ref,
		use.kind,
		use.location,
	)
}
