package gateway

import (
	"encoding/json"
	"errors"
)

const readToolCallVersion = "read-tool-call-v1"

// Tool declarations authorize only a response shape, never execution or a
// resource grant. The executor must still use ToolInvoke with its own identity.
func protectedToolDeclaration(input map[string]json.RawMessage) (bool, error) {
	invalid := errors.New("unsupported_tool_contract")
	for _, key := range []string{"functions", "function_call"} {
		if value, ok := input[key]; ok && string(value) != "null" {
			return false, invalid
		}
	}
	value, ok := input["tools"]
	if !ok || string(value) == "null" {
		return false, nil
	}
	var tools []struct {
		Type     string `json:"type"`
		Function struct {
			Name       string `json:"name"`
			Parameters struct {
				Type       string `json:"type"`
				Properties map[string]struct {
					Type string `json:"type"`
				} `json:"properties"`
				Required   []string `json:"required"`
				Additional *bool    `json:"additionalProperties"`
			} `json:"parameters"`
		} `json:"function"`
	}
	if json.Unmarshal(value, &tools) != nil {
		return false, invalid
	}
	if len(tools) == 0 {
		return false, nil
	}
	if len(tools) != 1 {
		return false, invalid
	}
	t := tools[0]
	p := t.Function.Parameters
	if t.Type != "function" || t.Function.Name != "read_resource" || p.Type != "object" || len(p.Properties) != 1 || p.Properties["resource_id"].Type != "string" || len(p.Required) != 1 || p.Required[0] != "resource_id" || p.Additional == nil || *p.Additional {
		return false, invalid
	}
	return true, nil
}

// Canonical IDs discard unchecked provider identifiers. Arguments are decoded
// before detection and serialized afresh, so escapes cannot hide their value.
func projectReadToolCall(raw json.RawMessage, requestID string) (any, string, error) {
	invalid := errors.New("unsupported_tool_call")
	var calls []struct {
		Type     string `json:"type"`
		Function struct {
			Name      string `json:"name"`
			Arguments string `json:"arguments"`
		} `json:"function"`
	}
	if json.Unmarshal(raw, &calls) != nil || len(calls) != 1 || calls[0].Type != "function" || calls[0].Function.Name != "read_resource" {
		return nil, "", invalid
	}
	resource, err := toolStringObject([]byte(calls[0].Function.Arguments), "resource_id")
	if err != nil || !toolArgumentID.MatchString(resource) {
		return nil, "", invalid
	}
	arguments, _ := json.Marshal(map[string]string{"resource_id": resource})
	return []any{map[string]any{"id": "call_" + requestID, "type": "function", "function": map[string]string{"name": "read_resource", "arguments": string(arguments)}}}, resource, nil
}
