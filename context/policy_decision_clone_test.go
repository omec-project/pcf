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
// land together and take the process down. The same goes for a map whose entries are pointers: the
// entry has to come back as a different object too, or a write through the stored one is a write
// into the snapshot.
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

			continue
		}

		if before.Kind() == reflect.Pointer {
			before, after = before.Elem(), after.Elem()
		}
		if before.Kind() != reflect.Map || before.Type().Elem().Kind() != reflect.Pointer {
			continue
		}
		key := before.MapKeys()[0]
		if before.MapIndex(key).Pointer() == after.MapIndex(key).Pointer() {
			t.Errorf("%s's entry is the same object in the clone, so a write through the stored entry "+
				"is a write into the snapshot: copy its entries in CloneSmPolicyDecisionContainers", name)
		}
	}
}

// mapWithOneEntry makes a map of the given type holding one zero-keyed entry. Where the entries are
// pointers the entry is a real one, not nil, so that a clone sharing it can be told from one that
// copied it.
func mapWithOneEntry(mapType reflect.Type) reflect.Value {
	made := reflect.MakeMap(mapType)
	entry := reflect.New(mapType.Elem()).Elem()
	if mapType.Elem().Kind() == reflect.Pointer {
		entry = reflect.New(mapType.Elem().Elem())
	}
	made.SetMapIndex(reflect.New(mapType.Key()).Elem(), entry)

	return made
}

// The point of the clone, stated as behaviour rather than as object identity: a write the
// application-function path makes after a snapshot was taken must not appear in what was sent.
func TestCloneSmPolicyDecisionContainersDoesNotSeeLaterWrites(t *testing.T) {
	charging := map[string]*models.ChargingData{"chg-1": models.NewChargingData("chg-1")}
	src := models.SmPolicyDecision{ChgDecs: charging}

	published := CloneSmPolicyDecisionContainers(src)
	// What the sponsored-connectivity path does to the stored decision: it adds an entry, and it
	// changes one it already holds through the stored pointer.
	charging["chg-2"] = models.NewChargingData("chg-2")
	charging["chg-1"].SetSponsorId("sponsor-1")

	if _, found := published.ChgDecs["chg-2"]; found {
		t.Error("the snapshot sees a write made after it was taken, so it shares the map")
	}
	entry, found := published.ChgDecs["chg-1"]
	if !found {
		t.Fatal("the snapshot lost an entry that was there when it was taken")
	}
	if entry.HasSponsorId() {
		t.Error("the snapshot sees a write made through the stored entry, so it shares the entry")
	}
}

// The one field below an entry that a handler writes through: DEF_QOS_CH fetches a session rule's
// AuthDefQos and calls its setters. A snapshot that copied the rule but shared that struct would
// carry the change into a notification being marshalled with no lock held.
func TestCloneSmPolicyDecisionContainersDoesNotSeeDefaultQosWrites(t *testing.T) {
	authDefQos := models.NewAuthorizedDefaultQos()
	authDefQos.SetVar5qi(9)
	rule := models.NewSessionRuleWithDefaults()
	rule.SetSessRuleId("sess-1")
	rule.AuthDefQos = authDefQos
	src := models.SmPolicyDecision{}
	src.SetSessRules(map[string]*models.SessionRule{"sess-1": rule})

	published := CloneSmPolicyDecisionContainers(src)
	// What the DEF_QOS_CH handler does to the stored decision.
	authDefQos.SetVar5qi(5)

	if got := (*published.SessRules)["sess-1"].AuthDefQos.GetVar5qi(); got != 9 {
		t.Errorf("snapshot's default QoS 5QI = %d, want 9: it shares AuthDefQos with the stored rule", got)
	}
}
