package state

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

const (
	DeviceExpirySchedule  = "schedule"
	DeviceExpiryDisable   = "disable"
	DeviceExpiryExtend    = "extend"
	DeviceExpiryExpire    = "expire"
	MaxDeviceExpiry       = 180 * 24 * time.Hour
	DeviceExpiryExtension = 30 * time.Minute
)

var (
	ErrDeviceExpiryInvalid = errors.New("invalid device expiry setting")
	ErrDeviceExpired       = errors.New("device key expired; temporarily extend it before changing expiry")
	ErrDeviceNotExpired    = errors.New("only expired devices can be temporarily extended")
)

type DeviceExpiryUpdate struct {
	Revision        string     `json:"revision"`
	Mode            string     `json:"mode"`
	ExpiresAt       *time.Time `json:"expires_at,omitempty"`
	DurationSeconds *int64     `json:"duration_seconds,omitempty"`
}

func (update DeviceExpiryUpdate) expiryAt(now time.Time) (time.Time, error) {
	switch update.Mode {
	case DeviceExpirySchedule:
		if (update.ExpiresAt == nil) == (update.DurationSeconds == nil) {
			return time.Time{}, ErrDeviceExpiryInvalid
		}
		if update.DurationSeconds != nil {
			// 先验证整数范围再转 Duration，不能让超大输入溢出成合法短时间。
			if *update.DurationSeconds < 1 || *update.DurationSeconds > int64(MaxDeviceExpiry/time.Second) {
				return time.Time{}, ErrDeviceExpiryInvalid
			}
			return now.Add(time.Duration(*update.DurationSeconds) * time.Second), nil
		}
		if !update.ExpiresAt.After(now) || update.ExpiresAt.After(now.Add(MaxDeviceExpiry)) {
			return time.Time{}, ErrDeviceExpiryInvalid
		}
		return update.ExpiresAt.UTC(), nil
	case DeviceExpiryDisable, DeviceExpiryExtend, DeviceExpiryExpire:
		if update.ExpiresAt != nil || update.DurationSeconds != nil {
			return time.Time{}, ErrDeviceExpiryInvalid
		}
		switch update.Mode {
		case DeviceExpiryExtend:
			return now.Add(DeviceExpiryExtension), nil
		case DeviceExpiryExpire:
			return now, nil
		default:
			return time.Time{}, nil
		}
	default:
		return time.Time{}, ErrDeviceExpiryInvalid
	}
}

// UpdateNodeExpiryTx 必须在租户写锁和持久权限检查之后调用；只能更新密钥有效期。
func UpdateNodeExpiryTx(ctx context.Context, transaction *sql.Tx, reference string, update DeviceExpiryUpdate, now time.Time) (Node, bool, error) {
	expiry, err := update.expiryAt(now.UTC())
	if err != nil {
		return Node{}, false, err
	}
	node, err := ReadRouteNode(ctx, transaction, reference)
	if err != nil {
		return Node{}, false, err
	}
	if NodeExpiryRevision(node) != update.Revision {
		return Node{}, false, ErrDeviceChanged
	}
	expired := !node.Expiry.IsZero() && !node.Expiry.After(now)
	if update.Mode == DeviceExpiryExtend && !expired {
		return Node{}, false, ErrDeviceNotExpired
	}
	if expired {
		switch update.Mode {
		case DeviceExpiryExpire:
			return node, false, nil
		case DeviceExpiryExtend:
		default:
			return Node{}, false, ErrDeviceExpired
		}
	}
	if node.Expiry.Equal(expiry) {
		return node, false, nil
	}
	result, err := transaction.ExecContext(ctx, "UPDATE nodes SET expiry = ? WHERE id = ?", nullableTimePtr(expiry), int64(node.ID))
	if err != nil {
		return Node{}, false, err
	}
	if err := requireSingleRow(result); err != nil {
		return Node{}, false, err
	}
	node.Expiry = expiry
	return node, true, nil
}
