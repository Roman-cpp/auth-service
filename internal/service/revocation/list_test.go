package revocation

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/krypton/auth-service/internal/domain/auth"
	"github.com/krypton/auth-service/internal/domain/user"
)

type staticSource map[user.UserID]int64

func (s staticSource) TokenRevocations(context.Context) (map[user.UserID]int64, error) {
	return s, nil
}

// Список, который давно не обновлялся, не принимает ни одного токена:
// пропущенный за это время отзыв иначе остался бы незамеченным.
func TestStaleRevocationListFailsClosed(t *testing.T) {
	l := NewList(staticSource{})
	if err := l.Sync(t.Context()); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if err := l.Check("user-1", 1); err != nil {
		t.Fatalf("fresh list rejected a token: %v", err)
	}

	l.now = func() time.Time { return time.Now().Add(maxStaleness + time.Second) }

	if err := l.Check("user-1", 1); !errors.Is(err, auth.ErrRevocationsStale) {
		t.Errorf("got %v, want ErrRevocationsStale", err)
	}
}
