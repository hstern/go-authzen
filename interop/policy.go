// Copyright 2026 The go-authzen Authors
// SPDX-License-Identifier: Apache-2.0

package interop

import "encoding/json"

// Decide returns the Todo scenario's expected decision for one access
// evaluation. It encodes the role-based authorization rules the
// upstream PEP (authzen-todo-backend) and the participating PDPs
// agreed at Identiverse 2024:
//
//   - admin:  any action on any resource is allowed
//   - editor: may create any todo and read any user or todo; may
//     update or delete a todo only when its OwnerID matches
//     the editor's subject ID
//   - viewer: may read any user or todo; everything else is denied
//
// The function intentionally returns false rather than an error for
// unknown subjects, actions, or resource types — the PDP role in the
// interop scenario maps every undefined request to "deny", matching
// what the participating PDPs do.
//
// resourceProperties is the wire-shape `properties` field for the
// resource. For todo updates and deletes it carries
// {"ownerID": "<user-id>"}; for other actions it is ignored. A nil
// or empty value is treated as "no properties on the wire".
func Decide(subjectID, action, resourceType, resourceID string, resourceProperties json.RawMessage) bool {
	user, ok := UserByID(subjectID)
	if !ok {
		return false
	}
	if user.HasRole("admin") {
		return true
	}
	switch action {
	case ActionReadUser:
		return resourceType == ResourceTypeUser
	case ActionReadTodos:
		return resourceType == ResourceTypeTodo
	case ActionCreateTodo:
		return resourceType == ResourceTypeTodo && user.HasRole("editor")
	case ActionUpdateTodo, ActionDeleteTodo:
		if resourceType != ResourceTypeTodo || !user.HasRole("editor") {
			return false
		}
		return ownerMatches(subjectID, resourceID, resourceProperties)
	}
	return false
}

// ownerMatches reports whether the resource belongs to the subject. It
// prefers the ownerID carried in the wire-shape properties (what the
// upstream PEP sends) and falls back to the fixture todo lookup so
// tests can omit properties when they are not under test.
func ownerMatches(subjectID, resourceID string, properties json.RawMessage) bool {
	if len(properties) > 0 {
		var p struct {
			OwnerID string `json:"ownerID"`
		}
		if err := json.Unmarshal(properties, &p); err == nil && p.OwnerID != "" {
			return p.OwnerID == subjectID
		}
	}
	t, ok := TodoByID(resourceID)
	if !ok {
		return false
	}
	return t.OwnerID == subjectID
}
