// Package contracts embeds the normative, machine-readable control-plane
// artifacts (Stage x Action Matrix and JSON Schemas) so that runtime services
// validate against the exact same source of truth that humans review.
package contracts

import _ "embed"

// StageActionMatrixJSON is the embedded v1.6 §2 Stage x Action Matrix (canonical
// machine artifact). The YAML form in the spec doc mirrors this file. JSON is
// used so the loader has zero external dependencies (stdlib encoding/json).
//
//go:embed stage_action_matrix.json
var StageActionMatrixJSON []byte

// ContextSchemaJSON is the embedded Context JSON Schema (v1.6 §7 baseline).
//
//go:embed schema/context.schema.json
var ContextSchemaJSON []byte

// SignalSchemaJSON is the embedded Signal JSON Schema (v1.6 §8 baseline).
//
//go:embed schema/signal.schema.json
var SignalSchemaJSON []byte

// DecisionSchemaJSON is the embedded Decision Contract JSON Schema (v1.6 §11 baseline).
//
//go:embed schema/decision.schema.json
var DecisionSchemaJSON []byte
