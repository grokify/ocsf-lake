package integrity

import (
	"context"
	"time"
)

// RunPeriodicIncremental runs CheckIncremental every interval, advancing the
// checkpoint across runs, until ctx is canceled. onReport is called after
// every run with the report, the checkpoint to persist, and any error; a nil
// onReport discards results. The call blocks; run it in a goroutine.
func (c *Checker) RunPeriodicIncremental(ctx context.Context, interval time.Duration, start Checkpoint, onReport func(*Report, Checkpoint, error)) {
	cp := start
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			report, next, err := c.CheckIncremental(ctx, cp)
			if err == nil {
				cp = next
			}
			if onReport != nil {
				onReport(report, cp, err)
			}
		}
	}
}

// RunPeriodicSample runs CheckSample every interval until ctx is canceled.
// Combined with SamplePolicy.MaxEvents this bounds checking cost per period,
// e.g. a monthly budget of N events at a daily cadence is MaxEvents = N/30.
// The call blocks; run it in a goroutine.
func (c *Checker) RunPeriodicSample(ctx context.Context, interval time.Duration, sp SamplePolicy, onReport func(*Report, error)) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			report, err := c.CheckSample(ctx, sp)
			if onReport != nil {
				onReport(report, err)
			}
		}
	}
}
