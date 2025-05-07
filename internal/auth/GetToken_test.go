package auth

import (
	"net/http"
	"testing"
)

func TestGetToken(t *testing.T) {
	tests := []struct {
		name      string
		headerVal string
		token     string
		shouldErr bool
	}{
		{
			name:      "Valid token",
			headerVal: "Bearer asdfasdf",
			token:     "asdfasdf",
		},
		{
			name:      "valid token with a lot space",
			headerVal: "Bearer                              asdfasdf",
			token:     "asdfasdf",
		},
		{
			name:      "Invalid prefix",
			headerVal: "WrongPrefix asdfasdf",
			shouldErr: true,
		},
		{
			name:      "No header",
			headerVal: "",
			shouldErr: true,
		},
		{
			name:      "No token",
			headerVal: "Bearer  ",
			shouldErr: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			h := http.Header{}
			if test.headerVal != "" {
				h.Set("Authorization", test.headerVal)
			}
			RetTToken, err := GetToken(h)
			if test.shouldErr {
				if err == nil {
					t.Error("Expected error, got nil")
				}
			} else {
				if err != nil {
					t.Fatalf("Got error, expected nil, got %v", err)
				}
				if RetTToken != test.token {
					t.Errorf("Expected token %s, got %s", test.token, RetTToken)
				}
			}
		})
	}
}
