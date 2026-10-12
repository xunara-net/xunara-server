package state

import (
	"errors"
	"math"
	"testing"
	"time"
)

func TestDeviceExpiryTimeValidation(test *testing.T) {
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	seconds := func(value int64) *int64 { return &value }
	instant := func(value time.Time) *time.Time { return &value }
	for _, update := range []DeviceExpiryUpdate{
		{Mode: "unknown"}, {Mode: DeviceExpirySchedule},
		{Mode: DeviceExpirySchedule, DurationSeconds: seconds(0)},
		{Mode: DeviceExpirySchedule, DurationSeconds: seconds(-1)},
		{Mode: DeviceExpirySchedule, DurationSeconds: seconds(math.MaxInt64)},
		{Mode: DeviceExpirySchedule, DurationSeconds: seconds(int64(MaxDeviceExpiry/time.Second) + 1)},
		{Mode: DeviceExpirySchedule, ExpiresAt: instant(now)},
		{Mode: DeviceExpirySchedule, ExpiresAt: instant(now.Add(-time.Second))},
		{Mode: DeviceExpirySchedule, ExpiresAt: instant(now.Add(MaxDeviceExpiry + time.Nanosecond))},
		{Mode: DeviceExpirySchedule, ExpiresAt: instant(time.Time{})},
		{Mode: DeviceExpirySchedule, DurationSeconds: seconds(60), ExpiresAt: instant(now.Add(time.Hour))},
		{Mode: DeviceExpiryDisable, DurationSeconds: seconds(0)},
		{Mode: DeviceExpiryExtend, ExpiresAt: instant(now)},
		{Mode: DeviceExpiryExpire, DurationSeconds: seconds(1)},
	} {
		if _, err := update.expiryAt(now); !errors.Is(err, ErrDeviceExpiryInvalid) {
			test.Fatalf("invalid update accepted: %+v %v", update, err)
		}
	}
	for _, fixture := range []struct {
		update DeviceExpiryUpdate
		want   time.Time
	}{
		{DeviceExpiryUpdate{Mode: DeviceExpirySchedule, DurationSeconds: seconds(1)}, now.Add(time.Second)},
		{DeviceExpiryUpdate{Mode: DeviceExpirySchedule, DurationSeconds: seconds(int64(MaxDeviceExpiry / time.Second))}, now.Add(MaxDeviceExpiry)},
		{DeviceExpiryUpdate{Mode: DeviceExpirySchedule, ExpiresAt: instant(now.Add(time.Hour).In(time.FixedZone("UTC+8", 8*3600)))}, now.Add(time.Hour)},
		{DeviceExpiryUpdate{Mode: DeviceExpiryDisable}, time.Time{}},
		{DeviceExpiryUpdate{Mode: DeviceExpiryExtend}, now.Add(30 * time.Minute)},
		{DeviceExpiryUpdate{Mode: DeviceExpiryExpire}, now},
	} {
		got, err := fixture.update.expiryAt(now)
		if err != nil || !got.Equal(fixture.want) || got.Location() != time.UTC {
			test.Fatalf("expiry: %v %v, want %v", got, err, fixture.want)
		}
	}
}
