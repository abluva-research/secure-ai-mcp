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

package pseudokey

import "context"

type contextKey struct{}

// WithVirtualIdentity returns a new context with the virtual identity key attached.
func WithVirtualIdentity(ctx context.Context, key string) context.Context {
	return context.WithValue(ctx, contextKey{}, key)
}

// FromContext extracts the virtual identity key from the context, if present.
func FromContext(ctx context.Context) (string, bool) {
	key, ok := ctx.Value(contextKey{}).(string)
	return key, ok && key != ""
}
