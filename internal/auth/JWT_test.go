package auth

import (
	"github.com/google/uuid"
	"testing"
	"time"
)

func TestJWT(t *testing.T) {
	userID := uuid.New()
	tests := []struct {
		name      string
		secret    string
		expiresIn time.Duration
		modify    func(string) string
		checkWith string
		shouldErr bool
	}{
		{
			name:      "Valid JWT",
			secret:    "secret",
			expiresIn: time.Minute,
			checkWith: "secret",
		},
		{
			name:      "Expired JWT",
			secret:    "secret",
			expiresIn: -time.Minute,
			checkWith: "secret",
			shouldErr: true,
		},
		{
			name:      "Invalid secret",
			secret:    "secret",
			expiresIn: time.Minute,
			checkWith: "Wrong-secret",
			shouldErr: true,
		},
		{
			name:      "Bad JWT",
			secret:    "secret",
			expiresIn: time.Minute,
			modify:    func(s string) string { return "Wrong JWT" },
			checkWith: "secret",
			shouldErr: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			token, err := MakeJWT(userID, test.secret, test.expiresIn)
			if err != nil {
				t.Fatal(err)
			}
			if test.modify != nil {
				token = test.modify(token)
			}
			parsedId, err := ValidateJWT(token, test.checkWith)
			if test.shouldErr {
				if err == nil {
					t.Errorf("Expected error but got nil(userID: %v)", parsedId)
				} else {
					t.Logf("Expected error: %v", err)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if parsedId != userID {
					t.Errorf("parsed ID is %s, want %s", parsedId, userID)
				}
			}
		})
	}
}
