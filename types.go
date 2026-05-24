// Copyright 2026 The go-authzen Authors
// SPDX-License-Identifier: Apache-2.0

package authzen

import (
	"bytes"
	"encoding/json"
)

// Subject identifies the entity whose authorization is being evaluated.
// Per AuthZEN 1.0 §5.1.1, a subject has a Type (e.g. "user", "service"),
// an ID that uniquely identifies the subject within that type, and an
// optional Properties payload for extension attributes.
//
// Properties is a [json.RawMessage] so it round-trips byte-stably and so
// consumers pay no deserialization cost for fields they don't read. To
// inspect or build properties as a typed extension, use [DecodeJSON] and
// [EncodeJSON].
type Subject struct {
	Type       string          `json:"type"`
	ID         string          `json:"id,omitempty"`
	Properties json.RawMessage `json:"properties,omitempty"`
}

// Resource identifies the entity being accessed. Per AuthZEN 1.0 §5.1.3
// a resource has a Type (e.g. "document", "account"), an ID unique within
// that type, and optional extension Properties.
//
// In a Resource Search request the ID is omitted (see [ResourceSearchRequest]).
type Resource struct {
	Type       string          `json:"type"`
	ID         string          `json:"id,omitempty"`
	Properties json.RawMessage `json:"properties,omitempty"`
}

// Action identifies the operation being attempted on a resource. Per
// AuthZEN 1.0 §5.1.2 an action has a Name (e.g. "read", "delete") and
// optional extension Properties.
//
// Unlike Subject and Resource, an Action Search request omits the
// `action` key entirely from the request body (see [ActionSearchRequest]).
type Action struct {
	Name       string          `json:"name"`
	Properties json.RawMessage `json:"properties,omitempty"`
}

// PageRequest is the pagination input on Search requests. Per AuthZEN
// 1.0 §6.1.3, Token carries an opaque cursor from a previous response's
// NextToken; Limit is the maximum number of results to return; Properties
// is an optional extension payload.
//
// All other request parameters MUST remain identical across pages when
// reusing a Token — varying them produces undefined behavior.
type PageRequest struct {
	Token      string          `json:"token,omitempty"`
	Limit      int             `json:"limit,omitempty"`
	Properties json.RawMessage `json:"properties,omitempty"`
}

// PageResponse is the pagination output on Search responses. Per AuthZEN
// 1.0 §6.1.4, NextToken is an opaque cursor that the caller passes in
// the next PageRequest to fetch the next page. An empty string (NOT
// absent, NOT null — empty) signals the end of results. Count and Total
// are optional advisory counts.
//
// The library round-trips an empty NextToken verbatim so the spec's
// end-of-results sentinel is preserved across encode and decode.
type PageResponse struct {
	NextToken  string          `json:"next_token"`
	Count      int             `json:"count,omitempty"`
	Total      int             `json:"total,omitempty"`
	Properties json.RawMessage `json:"properties,omitempty"`
}

// DecodeJSON decodes raw into v. It treats a nil or empty raw as "no
// extension present" — v is left unchanged and the call returns nil
// rather than failing with an unexpected-EOF error. This matches the
// AuthZEN convention that Properties / Context fields are optional and
// absent fields are normal, not exceptional.
//
// For any non-empty input, DecodeJSON delegates to [json.Unmarshal].
// Use it to read a typed extension out of a [Subject.Properties],
// [Resource.Properties], [Action.Properties], or any other
// [json.RawMessage] field on a request or response.
func DecodeJSON(raw json.RawMessage, v any) error {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	return json.Unmarshal(raw, v)
}

// EncodeJSON encodes v into a [json.RawMessage]. If v is nil it returns
// a nil RawMessage so the encoded field is omitted under
// `omitempty` JSON tags. Otherwise it delegates to [json.Marshal].
//
// Use it to populate a Properties field with a typed extension while
// preserving byte-stable round-trips for any other consumer that only
// reads the field as opaque bytes.
func EncodeJSON(v any) (json.RawMessage, error) {
	if v == nil {
		return nil, nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return b, nil
}
