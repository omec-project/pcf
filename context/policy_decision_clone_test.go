// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"reflect"
	"testing"

	"github.com/omec-project/openapi/v2/models"
)

// A snapshot is only a snapshot if it shares nothing, and the list of containers to clone is
// written by hand against a generated model. This walks the model instead: it populates every map
// and slice it declares, clones, and asserts each one came back as a different object.
//
// So a container the clone misses fails here, and so does one the model gains later — which is the
// case that matters, because the sharing it reintroduces is silent until a map read and a map write
// land together and take the process down.
func TestCloneSmPolicyDecisionContainersCoversEveryContainer(t *testing.T) {
	var src models.SmPolicyDecision
	value := reflect.ValueOf(&src).Elem()
	declared := value.Type()

	var containers []string
	for i := range declared.NumField() {
		field := declared.Field(i)
		fieldValue := value.Field(i)

		switch field.Type.Kind() {
		case reflect.Map:
			fieldValue.Set(mapWithOneEntry(field.Type))
		case reflect.Slice:
			fieldValue.Set(reflect.MakeSlice(field.Type, 1, 1))
		case reflect.Pointer:
			// An optional map in the generated models is a pointer to a map.
			if field.Type.Elem().Kind() != reflect.Map {
				continue
			}
			held := reflect.New(field.Type.Elem())
			held.Elem().Set(mapWithOneEntry(field.Type.Elem()))
			fieldValue.Set(held)
		default:
			continue
		}
		containers = append(containers, field.Name)
	}

	if len(containers) == 0 {
		t.Fatal("no containers found on the model, so every assertion below passes against nothing")
	}

	cloned := reflect.ValueOf(CloneSmPolicyDecisionContainers(src))
	for _, name := range containers {
		before := value.FieldByName(name)
		after := cloned.FieldByName(name)
		if before.Pointer() == after.Pointer() {
			t.Errorf("%s is the same object in the clone, so a snapshot still shares it with the "+
				"stored decision: add it to CloneSmPolicyDecisionContainers", name)
		}
	}
}

func mapWithOneEntry(mapType reflect.Type) reflect.Value {
	made := reflect.MakeMap(mapType)
	made.SetMapIndex(reflect.New(mapType.Key()).Elem(), reflect.New(mapType.Elem()).Elem())

	return made
}

// The point of the clone, stated as behaviour rather than as object identity: a write the
// application-function path makes after a snapshot was taken must not appear in what was sent.
func TestCloneSmPolicyDecisionContainersDoesNotSeeLaterWrites(t *testing.T) {
	charging := map[string]models.ChargingData{"chg-1": {}}
	src := models.SmPolicyDecision{ChgDecs: charging}

	published := CloneSmPolicyDecisionContainers(src)
	// What the sponsored-connectivity path does to the stored decision.
	charging["chg-2"] = models.ChargingData{}

	if _, found := published.ChgDecs["chg-2"]; found {
		t.Error("the snapshot sees a write made after it was taken, so it shares the map")
	}
	if _, found := published.ChgDecs["chg-1"]; !found {
		t.Error("the snapshot lost an entry that was there when it was taken")
	}
}
