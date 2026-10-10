package state

import (
	"encoding/json"
	"strconv"
	"time"
)

// 执行报告是服务身份自报，不是独立探测证明；接收时间由服务端决定。
type RelayExecution struct {
	ConfigVersion  string `json:"config_version"`
	AppliedVersion string `json:"applied_version,omitempty"`
	Status         string `json:"status"`
	State          string `json:"state"`
	BandwidthLimit int64  `json:"bandwidth_limit"`
	ErrorCode      string `json:"error_code,omitempty"`
}

func (execution *RelayExecution) UnmarshalJSON(raw []byte) error {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return ErrRelayExecutionInvalid
	}
	for _, name := range []string{"config_version", "status", "state", "bandwidth_limit"} {
		value, found := fields[name]
		if !found || string(value) == "null" {
			return ErrRelayExecutionInvalid
		}
	}
	type payload RelayExecution
	var decoded payload
	if json.Unmarshal(raw, &decoded) != nil {
		return ErrRelayExecutionInvalid
	}
	*execution = RelayExecution(decoded)
	return nil
}

func executionVersion(version string) (uint64, bool) {
	parsed, err := strconv.ParseUint(version, 10, 64)
	return parsed, err == nil && parsed > 0 && parsed <= 1<<53-1 && strconv.FormatUint(parsed, 10) == version
}

func validateRelayExecution(relay Relay, execution RelayExecution) error {
	attempt, valid := executionVersion(execution.ConfigVersion)
	if !valid || attempt > relay.ConfigVersion || execution.BandwidthLimit < 0 || execution.BandwidthLimit > 1<<53-1 || !ValidRelayState(execution.State) && execution.State != "pending" {
		return ErrRelayExecutionInvalid
	}
	if !relay.ExecutionReportedAt.IsZero() {
		previous, _ := executionVersion(relay.Execution.ConfigVersion)
		if attempt < previous {
			return ErrRelayExecutionInvalid
		}
	}
	if execution.AppliedVersion != "" {
		applied, valid := executionVersion(execution.AppliedVersion)
		if !valid || applied > attempt {
			return ErrRelayExecutionInvalid
		}
	}
	switch execution.Status {
	case "applied":
		if execution.AppliedVersion != execution.ConfigVersion || execution.State == "pending" || execution.ErrorCode != "" {
			return ErrRelayExecutionInvalid
		}
		if attempt == relay.ConfigVersion && (execution.State != relay.DesiredState || relay.BandwidthLimit > 0 && execution.BandwidthLimit != relay.BandwidthLimit || relay.BandwidthLimit == -1 && execution.BandwidthLimit != 0) {
			return ErrRelayExecutionInvalid
		}
	case "failed":
		switch execution.ErrorCode {
		case "cache_write_failed", "apply_failed", "config_invalid", "version_conflict":
		default:
			return ErrRelayExecutionInvalid
		}
	default:
		return ErrRelayExecutionInvalid
	}
	return nil
}

// 两种存储复用校验与状态更新；旧进程省略回执时清为未知，不拼接历史成功。
func applyRelayHeartbeat(relay Relay, heartbeat RelayHeartbeat, now time.Time) (Relay, bool, error) {
	if relay.DesiredState == RelayStateRevoked {
		return Relay{}, false, ErrRelayRevoked
	}
	if heartbeat.UptimeSeconds < 0 || heartbeat.ConnectedClients < 0 || heartbeat.BytesIn < 0 || heartbeat.BytesOut < 0 || len(heartbeat.Version) > 64 {
		return Relay{}, false, ErrRelayExecutionInvalid
	}
	before, reported := relay.Execution, !relay.ExecutionReportedAt.IsZero()
	if heartbeat.Execution != nil {
		if err := validateRelayExecution(relay, *heartbeat.Execution); err != nil {
			return Relay{}, false, err
		}
		relay.Execution, relay.ExecutionReportedAt = *heartbeat.Execution, now
	} else {
		relay.Execution, relay.ExecutionReportedAt = RelayExecution{}, time.Time{}
	}
	relay.Healthy, relay.UptimeSeconds, relay.ConnectedClients = heartbeat.Healthy, heartbeat.UptimeSeconds, heartbeat.ConnectedClients
	relay.BytesIn, relay.BytesOut = heartbeat.BytesIn, heartbeat.BytesOut
	relay.LastSeen = now
	if !heartbeat.LastSeen.IsZero() {
		relay.LastSeen = heartbeat.LastSeen.UTC()
	}
	if heartbeat.Version != "" {
		relay.Version = heartbeat.Version
	}
	return relay, before != relay.Execution || reported != !relay.ExecutionReportedAt.IsZero(), nil
}
