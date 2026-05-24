// Copyright 2026 The go-authzen Authors
// SPDX-License-Identifier: Apache-2.0

package interop

import "encoding/json"

// PublicPDPBaseURL is the live Todo PDP the OpenID AuthZEN WG exposes
// for conformance testing. Tests with the `interop` build tag exercise
// this endpoint.
const PublicPDPBaseURL = "https://todo.authzen-interop.net"

// SubjectType is the AuthZEN subject type the Todo scenario uses for
// every authenticated user.
const SubjectType = "user"

// Resource types the Todo scenario sends to the PDP.
const (
	ResourceTypeUser = "user"
	ResourceTypeTodo = "todo"
)

// Action names the Todo PEP (authzen-todo-backend/src/auth.ts) sends
// to the PDP. The naming style — snake_case verb_noun — is the
// scenario's, not the spec's, and is reproduced verbatim so that wire
// payloads compare byte-stably against the upstream PEP's.
const (
	ActionReadUser   = "can_read_user"
	ActionReadTodos  = "can_read_todos"
	ActionCreateTodo = "can_create_todo"
	ActionUpdateTodo = "can_update_todo"
	ActionDeleteTodo = "can_delete_todo"
)

// User is one of the five test users the Todo scenario authenticates.
// ID is the subject ID — the email-form identifier the Todo backend
// places in Subject.ID on the wire.
type User struct {
	ID    string
	Name  string
	Roles []string
}

// HasRole reports whether the user carries the named role. Rick is the
// only user with two roles (admin and evil_genius); for the scenario's
// authorization rules only the first matters, but both are preserved
// to mirror the upstream directory verbatim.
func (u User) HasRole(name string) bool {
	for _, r := range u.Roles {
		if r == name {
			return true
		}
	}
	return false
}

var users = []User{
	{ID: "rick@the-citadel.com", Name: "Rick Sanchez", Roles: []string{"admin", "evil_genius"}},
	{ID: "morty@the-citadel.com", Name: "Morty Smith", Roles: []string{"editor"}},
	{ID: "summer@the-smiths.com", Name: "Summer Smith", Roles: []string{"editor"}},
	{ID: "beth@the-smiths.com", Name: "Beth Smith", Roles: []string{"viewer"}},
	{ID: "jerry@the-smiths.com", Name: "Jerry Smith", Roles: []string{"viewer"}},
}

// Users returns the five scenario users in a deterministic order. The
// returned slice is a copy; callers may mutate it freely.
func Users() []User {
	out := make([]User, len(users))
	copy(out, users)
	return out
}

// UserByID returns the scenario user with the given subject ID. The
// boolean reports whether the lookup succeeded.
func UserByID(id string) (User, bool) {
	for _, u := range users {
		if u.ID == id {
			return u, true
		}
	}
	return User{}, false
}

// Todo is a fixture entry in the scenario's todo list. OwnerID is the
// subject ID of the user who created the todo and is the field the
// PDP consults to apply the editor-only-on-own-todos rule.
type Todo struct {
	ID      string
	OwnerID string
	Title   string
}

var todos = []Todo{
	{ID: "todo-1", OwnerID: "morty@the-citadel.com", Title: "Buy groceries"},
	{ID: "todo-2", OwnerID: "summer@the-smiths.com", Title: "Pick up Morty"},
	{ID: "todo-3", OwnerID: "rick@the-citadel.com", Title: "Run experiment"},
	{ID: "todo-4", OwnerID: "morty@the-citadel.com", Title: "Do homework"},
}

// Todos returns the fixture todo set in a deterministic order.
func Todos() []Todo {
	out := make([]Todo, len(todos))
	copy(out, todos)
	return out
}

// TodoByID returns the fixture todo with the given ID.
func TodoByID(id string) (Todo, bool) {
	for _, t := range todos {
		if t.ID == id {
			return t, true
		}
	}
	return Todo{}, false
}

// TodoProperties returns the wire-shape `properties` field for a todo
// resource — the JSON object the PEP sends so the PDP can apply the
// owner-only rule. The shape matches what authzen-todo-backend sends:
//
//	{"ownerID": "<user-id>"}
//
// The bytes are produced once and cached; the returned RawMessage is
// safe to share but callers should not mutate it.
func TodoProperties(t Todo) json.RawMessage {
	if cached, ok := todoPropsCache[t.ID]; ok {
		return cached
	}
	b, _ := json.Marshal(map[string]string{"ownerID": t.OwnerID})
	return b
}

var todoPropsCache = func() map[string]json.RawMessage {
	m := make(map[string]json.RawMessage, len(todos))
	for _, t := range todos {
		b, _ := json.Marshal(map[string]string{"ownerID": t.OwnerID})
		m[t.ID] = b
	}
	return m
}()
