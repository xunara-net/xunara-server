package state

import (
	"context"
	"fmt"
	"time"
)

func (store *SQLiteStore) RecordNodeLastSeen(node Node, seen time.Time) error {
	result, err := store.db.ExecContext(context.Background(), `UPDATE nodes
		SET last_seen = MAX(COALESCE(last_seen, 0), ?)
		WHERE id = ? AND stable_id = ? AND machine_key = ? AND node_key = ?`,
		seen.UnixNano(), int64(node.ID), node.StableID, node.MachineKey.String(), node.NodeKey.String())
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil || count != 1 {
		return fmt.Errorf("state: activity identity changed or update not persisted")
	}
	return nil
}

func (store *MemoryStore) RecordNodeLastSeen(node Node, seen time.Time) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	current, found := store.byID[node.ID]
	if !found || current.StableID != node.StableID || current.MachineKey != node.MachineKey || current.NodeKey != node.NodeKey {
		return fmt.Errorf("state: activity identity changed")
	}
	if current.LastSeen == nil || seen.After(*current.LastSeen) {
		current.LastSeen = &seen
		store.byID[node.ID] = current
	}
	return nil
}
