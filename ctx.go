package shopigo

import (
	"context"
	"time"
)

func SleepContext(ctx context.Context, t time.Duration) {
	ticker := time.NewTicker(t)
	defer ticker.Stop()
	select {
	case <-ctx.Done():
	case <-ticker.C:
	}
}
