package app

import (
	"encoding/json"
	"testing"
)

func TestSeedValue(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			// A JSON object is stored as its JSON, which is the shape a config
			// provider merges into an app's settings.
			name:  "object",
			input: `{"Host":"db.internal"}`,
			want:  `{"Host":"db.internal"}`,
		},
		{name: "string", input: `"placeholder"`, want: "placeholder"},
		{name: "string holding JSON", input: `"{\"a\":1}"`, want: `{"a":1}`},
		{name: "number", input: `42`, want: "42"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := seedValue(json.RawMessage(tt.input))
			if got == nil || *got != tt.want {
				t.Fatalf("seedValue(%s) = %v, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestParseSeedRejectsNonObjects(t *testing.T) {
	if _, err := parseSeed(`["a"]`); err == nil {
		t.Fatal("want an error for a JSON array, got nil")
	}
}
