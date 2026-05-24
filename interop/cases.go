// Copyright 2026 The go-authzen Authors
// SPDX-License-Identifier: Apache-2.0

package interop

import (
	"encoding/json"
	"fmt"
)

// Case is one (subject, action, resource) triple from the Todo
// scenario paired with its expected decision. Tests iterate Cases to
// drive the library in either role and assert each Decider returns
// ExpectedDecision.
//
// ResourceProperties is the wire-shape `properties` JSON object the
// PEP sends with the resource. For todo updates and deletes it
// carries {"ownerID": "<user-id>"}; for other actions it is nil.
type Case struct {
	Name               string
	SubjectID          string
	Action             string
	ResourceType       string
	ResourceID         string
	ResourceProperties json.RawMessage
	ExpectedDecision   bool
}

// Cases returns the curated table of evaluation cases derived from the
// Todo scenario's role rules. The set is deterministic and covers
// every (role × action) combination across at least one representative
// resource per action, plus owner / non-owner pairs for the editor
// update/delete rules.
//
// The expected decisions are computed by Decide so the table stays
// consistent with the rules; the sanity test in this package asserts
// that invariant.
func Cases() []Case {
	var cs []Case
	add := func(name, subject, action, rType, rID string, props json.RawMessage) {
		cs = append(cs, Case{
			Name:               name,
			SubjectID:          subject,
			Action:             action,
			ResourceType:       rType,
			ResourceID:         rID,
			ResourceProperties: props,
			ExpectedDecision:   Decide(subject, action, rType, rID, props),
		})
	}

	// can_read_user — every user may read any user's profile.
	for _, viewer := range users {
		for _, target := range users {
			add(
				fmt.Sprintf("%s reads %s's profile", short(viewer), short(target)),
				viewer.ID, ActionReadUser, ResourceTypeUser, target.ID, nil,
			)
		}
	}

	// can_read_todos — every user may read the todo list. The scenario's
	// upstream PEP sends a placeholder resource ID for the list-level
	// check; we mirror that with "todo-1".
	for _, u := range users {
		add(
			fmt.Sprintf("%s reads the todo list", short(u)),
			u.ID, ActionReadTodos, ResourceTypeTodo, "todo-1", nil,
		)
	}

	// can_create_todo — admin and editor allowed; viewer denied.
	for _, u := range users {
		add(
			fmt.Sprintf("%s creates a todo", short(u)),
			u.ID, ActionCreateTodo, ResourceTypeTodo, "todo-1", nil,
		)
	}

	// can_update_todo and can_delete_todo — admin always; editor only on
	// own todos; viewer never. Cover one own-todo and one other-owner
	// todo per editor; one todo per viewer; one per admin.
	for _, u := range users {
		for _, t := range todos {
			props := TodoProperties(t)
			ownership := "another user's"
			if t.OwnerID == u.ID {
				ownership = "their own"
			}
			add(
				fmt.Sprintf("%s updates %s todo (%s)", short(u), ownership, t.ID),
				u.ID, ActionUpdateTodo, ResourceTypeTodo, t.ID, props,
			)
			add(
				fmt.Sprintf("%s deletes %s todo (%s)", short(u), ownership, t.ID),
				u.ID, ActionDeleteTodo, ResourceTypeTodo, t.ID, props,
			)
		}
	}

	return cs
}

// short returns the user's given name for case descriptions.
func short(u User) string {
	for i, c := range u.Name {
		if c == ' ' {
			return u.Name[:i]
		}
	}
	return u.Name
}
