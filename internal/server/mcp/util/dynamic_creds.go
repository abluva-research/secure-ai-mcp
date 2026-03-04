// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package util

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/googleapis/genai-toolbox/internal/server/pseudokey"
	"github.com/googleapis/genai-toolbox/internal/sources"
	"github.com/googleapis/genai-toolbox/internal/tools"
)

// ParseDynamicCredentials extracts DynamicCredentials from a raw interface{} value
// provided in MCP tool call arguments as "db_credentials".
func ParseDynamicCredentials(raw any) (*sources.DynamicCredentials, error) {
	m, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("db_credentials must be a JSON object")
	}
	creds := &sources.DynamicCredentials{}
	if v, ok := m["host"].(string); ok {
		creds.Host = v
	}
	if v, ok := m["port"].(string); ok {
		creds.Port = v
	}
	if v, ok := m["user"].(string); ok {
		creds.User = v
	}
	if v, ok := m["password"].(string); ok {
		creds.Password = v
	}
	if v, ok := m["database"].(string); ok {
		creds.Database = v
	}
	if creds.Host == "" || creds.User == "" || creds.Database == "" {
		return nil, fmt.Errorf("db_credentials requires at least host, user, and database")
	}
	return creds, nil
}

// ExtractVirtualIdentity checks for "x-ablv-virtual-identity" in the data map
// and returns a new context with the virtual identity attached.
// Note: Does NOT remove the parameter from data map to allow validation to succeed.
func ExtractVirtualIdentity(ctx context.Context, data map[string]any) context.Context {
	if v, ok := data["x-ablv-virtual-identity"]; ok {
		if id, ok := v.(string); ok && id != "" {
			return pseudokey.WithVirtualIdentity(ctx, id)
		}
	}
	return ctx
}

// GetToolSourceName extracts the source name from a Tool via its config.
// Returns empty string if the tool config does not expose a source name.
func GetToolSourceName(t tools.Tool) string {
	cfg := t.ToConfig()
	cfgBytes, err := json.Marshal(cfg)
	if err != nil {
		return ""
	}
	var cfgMap map[string]any
	if err := json.Unmarshal(cfgBytes, &cfgMap); err != nil {
		return ""
	}
	// Check both cases: Go defaults to capitalized field name when no json tag
	for _, key := range []string{"source", "Source"} {
		if src, ok := cfgMap[key].(string); ok && src != "" {
			return src
		}
	}
	return ""
}
