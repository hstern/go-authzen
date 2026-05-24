// Copyright 2026 The go-authzen Authors
// SPDX-License-Identifier: Apache-2.0

package interop

import (
	"encoding/json"
	"testing"
)

func TestUsersAreUniqueAndDeterministic(t *testing.T) {
	a := Users()
	b := Users()
	if len(a) == 0 {
		t.Fatal("Users() returned no users")
	}
	if len(a) != len(b) {
		t.Fatalf("Users() length unstable: %d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i].ID != b[i].ID || a[i].Name != b[i].Name {
			t.Fatalf("Users() not deterministic at %d: %+v vs %+v", i, a[i], b[i])
		}
	}
	seen := make(map[string]bool, len(a))
	for _, u := range a {
		if seen[u.ID] {
			t.Errorf("duplicate user ID %q", u.ID)
		}
		seen[u.ID] = true
		if u.Name == "" {
			t.Errorf("user %q missing Name", u.ID)
		}
		if len(u.Roles) == 0 {
			t.Errorf("user %q has no roles", u.ID)
		}
	}
}

func TestUsersReturnsACopy(t *testing.T) {
	a := Users()
	a[0].Name = "mutated"
	b := Users()
	if b[0].Name == "mutated" {
		t.Fatalf("Users() leaked internal slice: caller mutation visible")
	}
}

func TestUserByID(t *testing.T) {
	u, ok := UserByID("rick@the-citadel.com")
	if !ok {
		t.Fatal("UserByID(rick@...) missing")
	}
	if !u.HasRole("admin") {
		t.Errorf("Rick should be admin, got roles %v", u.Roles)
	}
	if _, ok := UserByID("nobody@example.test"); ok {
		t.Error("UserByID returned true for unknown user")
	}
}

func TestTodosAreUniqueAndReferenceKnownOwners(t *testing.T) {
	seen := make(map[string]bool)
	for _, todo := range Todos() {
		if seen[todo.ID] {
			t.Errorf("duplicate todo ID %q", todo.ID)
		}
		seen[todo.ID] = true
		if _, ok := UserByID(todo.OwnerID); !ok {
			t.Errorf("todo %q has unknown owner %q", todo.ID, todo.OwnerID)
		}
	}
}

func TestTodoPropertiesAreValidJSON(t *testing.T) {
	for _, todo := range Todos() {
		props := TodoProperties(todo)
		var decoded map[string]string
		if err := json.Unmarshal(props, &decoded); err != nil {
			t.Fatalf("todo %q: invalid properties JSON: %v", todo.ID, err)
		}
		if decoded["ownerID"] != todo.OwnerID {
			t.Errorf("todo %q: properties ownerID = %q, want %q",
				todo.ID, decoded["ownerID"], todo.OwnerID)
		}
	}
}

// TestDecidePolicyShape exercises the documented role rules at a few
// representative points so a renaming or rule change shows up here
// before it shows up downstream.
func TestDecidePolicyShape(t *testing.T) {
	rick := "rick@the-citadel.com"    // admin
	morty := "morty@the-citadel.com"  // editor, owns todo-1 and todo-4
	summer := "summer@the-smiths.com" // editor, owns todo-2
	beth := "beth@the-smiths.com"     // viewer

	cases := []struct {
		name     string
		subject  string
		action   string
		rType    string
		rID      string
		props    json.RawMessage
		expected bool
	}{
		{"admin can delete anyone's todo", rick, ActionDeleteTodo, ResourceTypeTodo, "todo-1", TodoProperties(todos[0]), true},
		{"admin can read users", rick, ActionReadUser, ResourceTypeUser, beth, nil, true},
		{"editor can create", morty, ActionCreateTodo, ResourceTypeTodo, "todo-1", nil, true},
		{"editor can update own todo", morty, ActionUpdateTodo, ResourceTypeTodo, "todo-1", TodoProperties(todos[0]), true},
		{"editor cannot update other's todo", morty, ActionUpdateTodo, ResourceTypeTodo, "todo-2", TodoProperties(todos[1]), false},
		{"editor cannot delete other's todo", summer, ActionDeleteTodo, ResourceTypeTodo, "todo-1", TodoProperties(todos[0]), false},
		{"viewer can read todos", beth, ActionReadTodos, ResourceTypeTodo, "todo-1", nil, true},
		{"viewer cannot create", beth, ActionCreateTodo, ResourceTypeTodo, "todo-1", nil, false},
		{"viewer cannot update", beth, ActionUpdateTodo, ResourceTypeTodo, "todo-1", TodoProperties(todos[0]), false},
		{"unknown subject denied", "stranger@example.test", ActionReadUser, ResourceTypeUser, beth, nil, false},
		{"unknown action denied", morty, "can_smell_todos", ResourceTypeTodo, "todo-1", nil, false},
	}
	for _, tc := range cases {
		got := Decide(tc.subject, tc.action, tc.rType, tc.rID, tc.props)
		if got != tc.expected {
			t.Errorf("%s: Decide = %v, want %v", tc.name, got, tc.expected)
		}
	}
}

// TestCasesAreConsistentWithDecide is the load-bearing invariant: the
// Cases table is computed by calling Decide for every row, so any
// drift between the rules and the table is a bug in the helper, not
// in the data. Keeping the assertion here means a future refactor
// that splits the rule and the table apart still has to keep them in
// sync.
func TestCasesAreConsistentWithDecide(t *testing.T) {
	cs := Cases()
	if len(cs) == 0 {
		t.Fatal("Cases() returned no cases")
	}
	for _, c := range cs {
		want := Decide(c.SubjectID, c.Action, c.ResourceType, c.ResourceID, c.ResourceProperties)
		if c.ExpectedDecision != want {
			t.Errorf("%s: ExpectedDecision = %v, Decide = %v", c.Name, c.ExpectedDecision, want)
		}
	}
}

func TestCasesCoverEveryRoleActionCombination(t *testing.T) {
	want := map[string]bool{}
	for _, u := range Users() {
		for _, a := range []string{ActionReadUser, ActionReadTodos, ActionCreateTodo, ActionUpdateTodo, ActionDeleteTodo} {
			want[u.ID+"|"+a] = false
		}
	}
	for _, c := range Cases() {
		want[c.SubjectID+"|"+c.Action] = true
	}
	for key, covered := range want {
		if !covered {
			t.Errorf("no case covers %s", key)
		}
	}
}

func TestCasesAreDeterministic(t *testing.T) {
	a := Cases()
	b := Cases()
	if len(a) != len(b) {
		t.Fatalf("Cases() length unstable: %d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i].Name != b[i].Name || a[i].ExpectedDecision != b[i].ExpectedDecision {
			t.Fatalf("Cases() not deterministic at %d", i)
		}
	}
}
