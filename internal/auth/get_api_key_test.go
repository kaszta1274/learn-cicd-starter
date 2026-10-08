package auth_test

import (
	"errors"
	"net/http"
	"testing"

	"github.com/bootdotdev/learn-cicd-starter/internal/auth"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name    string
		input   http.Header
		want    string
		wantErr error
	}{
		{
			name:  "valid API key",
			input: http.Header{"Authorization": []string{"ApiKey test-key"}},
			want:  "test-key",
		},
		{
			name:    "missing authorization header",
			input:   http.Header{},
			wantErr: auth.ErrNoAuthHeaderIncluded,
		},
		{
			name:    "malformed authorization scheme",
			input:   http.Header{"Authorization": []string{"Bearer test-key"}},
			wantErr: errors.New("malformed authorization header"),
		},
		{
			name:    "missing API key",
			input:   http.Header{"Authorization": []string{"ApiKey"}},
			wantErr: errors.New("malformed authorization header"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := auth.GetAPIKey(tt.input)

			if got != tt.want {
				t.Errorf("GetAPIKey() got = %q, want %q", got, tt.want)
			}

			if tt.wantErr == nil {
				if err != nil {
					t.Errorf("GetAPIKey() unexpected error = %v", err)
				}
				return
			}

			if err == nil || err.Error() != tt.wantErr.Error() {
				t.Errorf("GetAPIKey() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}
