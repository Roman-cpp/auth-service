package auth

import (
	"context"
	"testing"
)

func TestIdentityRoundTrip(t *testing.T) {
	ctx := WithIdentity(context.Background(), Identity{UserID: "u-1", Role: "moderator"})

	if id, ok := UserIDFrom(ctx); !ok || id != "u-1" {
		t.Errorf("UserIDFrom = %q, %v", id, ok)
	}
	if role, ok := RoleFrom(ctx); !ok || role != "moderator" {
		t.Errorf("RoleFrom = %q, %v", role, ok)
	}
}

func TestMissingIdentity(t *testing.T) {
	ctx := context.Background()
	if _, ok := IdentityFrom(ctx); ok {
		t.Error("empty context must not carry an identity")
	}
	if id, ok := UserIDFrom(ctx); ok || id != "" {
		t.Errorf("UserIDFrom on empty context = %q, %v", id, ok)
	}
}

// Значение под чужим ключом с тем же «именем» личностью не считается:
// ключ — неэкспортируемый тип, а не строка.
func TestForeignKeyIsIgnored(t *testing.T) {
	ctx := context.WithValue(context.Background(), "user_id", "u-evil") //nolint:staticcheck // проверяем именно строковый ключ
	if _, ok := UserIDFrom(ctx); ok {
		t.Error("string key must not be mistaken for the identity")
	}
}
