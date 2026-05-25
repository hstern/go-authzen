// Cedar policies for the AuthZEN Todo conformance scenario.
//
// Three roles, modelled as parent entities the user is a member of:
//   - Role::"admin"  — any action on any resource is allowed
//   - Role::"editor" — read everything; create todos; update or delete
//                      a todo when its ownerID is the principal
//   - Role::"viewer" — read users and todos; nothing else
//
// The scenario also assigns Rick the unused role Role::"evil_genius";
// it is preserved in entities.json for fidelity with the upstream
// directory but no policy references it.
//
// Cedar's scope `principal in EXPR` accepts a single entity, not a
// set literal, so each role gets its own permit block rather than a
// shared `principal in [Role::"editor", Role::"viewer"]`. Action
// scope supports a set literal and uses it where the same role
// permits multiple actions.

// admin: unconditional permit.
permit (
    principal in Role::"admin",
    action,
    resource
);

// editor: read users + read todos + create todos (any resource).
permit (
    principal in Role::"editor",
    action in [Action::"can_read_user", Action::"can_read_todos", Action::"can_create_todo"],
    resource
);

// editor: update or delete a todo IFF its ownerID is the principal.
//
// `resource.ownerID` is an EntityRef attribute pointing at a User —
// see entities.json. Cedar compares EntityUIDs structurally, so the
// principal binding flows in directly.
permit (
    principal in Role::"editor",
    action in [Action::"can_update_todo", Action::"can_delete_todo"],
    resource is Todo
)
when {
    resource has ownerID && resource.ownerID == principal
};

// viewer: read users + read todos.
permit (
    principal in Role::"viewer",
    action in [Action::"can_read_user", Action::"can_read_todos"],
    resource
);
