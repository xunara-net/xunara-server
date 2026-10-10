package networkconfig

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

type RelayHistoryItem struct {
	state.RelayConfiguration
	Actor   string    `json:"actor"`
	Created time.Time `json:"created"`
}

func (store *SQLiteStore) RelayHistory(ctx context.Context, id string) ([]RelayHistoryItem, error) {
	documents, err := store.History(ctx, state.RelayConfigurationKind(id))
	if err != nil {
		return nil, err
	}
	items := make([]RelayHistoryItem, 0, len(documents))
	for _, document := range documents {
		configuration, err := decodeRelayConfiguration(document.Content, document.Revision)
		if err != nil {
			return nil, err
		}
		items = append(items, RelayHistoryItem{configuration, document.Actor, document.Created})
	}
	return items, nil
}

// 历史也属于持久配置边界；损坏的快照不能被缺省值补齐后当成成功恢复。
func decodeRelayConfiguration(content string, expected uint64) (state.RelayConfiguration, error) {
	var fields map[string]json.RawMessage
	if json.Unmarshal([]byte(content), &fields) != nil || len(fields) != 4 {
		return state.RelayConfiguration{}, errors.New("invalid stored relay configuration history")
	}
	for _, name := range []string{"config_version", "desired_state", "bandwidth_limit", "region_name"} {
		value, found := fields[name]
		if !found || string(value) == "null" {
			return state.RelayConfiguration{}, errors.New("invalid stored relay configuration history")
		}
	}
	var configuration state.RelayConfiguration
	if json.Unmarshal([]byte(content), &configuration) != nil || configuration.ConfigVersion != expected || !state.ValidRelayState(configuration.DesiredState) {
		return state.RelayConfiguration{}, errors.New("invalid stored relay configuration history")
	}
	relay := state.Relay{ConfigVersion: expected, DesiredState: configuration.DesiredState}
	update := state.RelayConfigUpdate{ConfigVersion: expected, DesiredState: configuration.DesiredState, BandwidthLimit: &configuration.BandwidthLimit, RegionName: &configuration.RegionName}
	if state.ValidateRelayConfigUpdate(relay, update) != nil {
		return state.RelayConfiguration{}, errors.New("invalid stored relay configuration history")
	}
	return configuration, nil
}

func (store *SQLiteStore) SaveRelay(ctx context.Context, id string, update state.RelayConfigUpdate, restore *uint64, writer Writer) (state.Relay, error) {
	return store.saveRelay(ctx, id, update, restore, &writer, writer.Actor())
}

// SavePlatformRelay 只由独立平台令牌门禁后的调用方使用，不接收租户 Session 代替平台身份。
func (store *SQLiteStore) SavePlatformRelay(ctx context.Context, id string, update state.RelayConfigUpdate, restore *uint64, organization string) (state.Relay, error) {
	if organization == "" {
		return state.Relay{}, identity.ErrNetworkWriterForbidden
	}
	return store.saveRelay(ctx, id, update, restore, nil, "platform:"+organization)
}

func (store *SQLiteStore) saveRelay(ctx context.Context, id string, update state.RelayConfigUpdate, restore *uint64, writer *Writer, actor string) (state.Relay, error) {
	transaction, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return state.Relay{}, err
	}
	defer transaction.Rollback()
	now := time.Now().UTC()
	if writer != nil {
		if err := identity.CheckNetworkWriter(ctx, transaction, writer.UserID, writer.SessionID, writer.APIKeyID, now); err != nil {
			return state.Relay{}, err
		}
	}
	action := identity.AuditRelayUpdated
	if restore != nil {
		var content string
		err := transaction.QueryRowContext(ctx, "SELECT content FROM network_document_history WHERE kind = ? AND revision = ?",
			state.RelayConfigurationKind(id), *restore).Scan(&content)
		if errors.Is(err, sql.ErrNoRows) {
			return state.Relay{}, ErrNotFound
		}
		if err != nil {
			return state.Relay{}, err
		}
		configuration, err := decodeRelayConfiguration(content, *restore)
		if err != nil {
			return state.Relay{}, err
		}
		update.DesiredState, update.BandwidthLimit, update.RegionName = configuration.DesiredState, &configuration.BandwidthLimit, &configuration.RegionName
		action = "relay.restored"
	}
	relay, err := state.UpdateRelayConfigTx(ctx, transaction, id, update, actor, now)
	if err != nil {
		return state.Relay{}, err
	}
	detail := fmt.Sprintf("configuration version %d; desired state %s", relay.ConfigVersion, relay.DesiredState)
	if restore != nil {
		detail += fmt.Sprintf("; restored from %d", *restore)
	}
	if err := commitChange(ctx, transaction, actor, action, "relay:"+id, detail, now); err != nil {
		return state.Relay{}, err
	}
	return relay, transaction.Commit()
}

func (store *SQLiteStore) DeleteRelay(ctx context.Context, id string, expected uint64, writer Writer) error {
	return store.deleteRelay(ctx, id, expected, &writer, writer.Actor())
}

func (store *SQLiteStore) DeletePlatformRelay(ctx context.Context, id string, expected uint64, organization string) error {
	if organization == "" {
		return identity.ErrNetworkWriterForbidden
	}
	return store.deleteRelay(ctx, id, expected, nil, "platform:"+organization)
}

func (store *SQLiteStore) deleteRelay(ctx context.Context, id string, expected uint64, writer *Writer, actor string) error {
	transaction, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	now := time.Now().UTC()
	if writer != nil {
		if err := identity.CheckNetworkWriter(ctx, transaction, writer.UserID, writer.SessionID, writer.APIKeyID, now); err != nil {
			return err
		}
	}
	if err := state.DeleteRelayTx(ctx, transaction, id, expected); err != nil {
		return err
	}
	if err := commitChange(ctx, transaction, actor, identity.AuditRelayDeleted, "relay:"+id, "deleted relay identity and configuration history", now); err != nil {
		return err
	}
	return transaction.Commit()
}
