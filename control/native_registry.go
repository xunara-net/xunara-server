package control

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

var errNativeScope = errors.New("native device scope is unavailable or conflicts")
var errNativeFlow = errors.New("native device enrollment expired or unavailable")

type nativeBinding struct {
	MachineKey   string
	NodeKey      string
	Organization string
	NoiseKey     string
}

type nativeFlow struct {
	ID           string
	MachineKey   string
	NodeKey      string
	Registration string
	Organization string
	NoiseKey     string
	Created      int64
	Expires      int64
}

func (registry *OrgRegistry) nativeBinding(ctx context.Context, machine, node string) (nativeBinding, bool, error) {
	var binding nativeBinding
	err := registry.db.QueryRowContext(ctx, "SELECT machine_key, node_key, org_id, noise_key FROM native_device_bindings WHERE machine_key = ? AND node_key = ?", machine, node).
		Scan(&binding.MachineKey, &binding.NodeKey, &binding.Organization, &binding.NoiseKey)
	if errors.Is(err, sql.ErrNoRows) {
		return binding, false, nil
	}
	return binding, err == nil, err
}

func bindNativeTx(ctx context.Context, transaction *sql.Tx, machine, node, organization, generation string) error {
	if machine == "" || node == "" || organization == "" || generation == "" {
		return errNativeScope
	}
	if _, err := transaction.ExecContext(ctx, `INSERT INTO native_device_bindings (machine_key, node_key, org_id, noise_key, created_at)
		VALUES (?, ?, ?, ?, ?) ON CONFLICT(machine_key, node_key) DO NOTHING`, machine, node, organization, generation, time.Now().UnixNano()); err != nil {
		return err
	}
	var actualOrg, actualGeneration string
	if err := transaction.QueryRowContext(ctx, "SELECT org_id, noise_key FROM native_device_bindings WHERE machine_key = ? AND node_key = ?", machine, node).Scan(&actualOrg, &actualGeneration); err != nil {
		return err
	}
	if actualOrg != organization || actualGeneration != generation {
		return errNativeScope
	}
	return nil
}

func (registry *OrgRegistry) bindNative(ctx context.Context, machine, node, organization, generation string) error {
	transaction, err := registry.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	if err := bindNativeTx(ctx, transaction, machine, node, organization, generation); err != nil {
		return err
	}
	return transaction.Commit()
}

const nativeFlowColumns = "id, machine_key, node_key, registration, org_id, noise_key, created_at, expires_at"

func scanNativeFlow(row interface{ Scan(...any) error }) (nativeFlow, error) {
	var flow nativeFlow
	err := row.Scan(&flow.ID, &flow.MachineKey, &flow.NodeKey, &flow.Registration, &flow.Organization, &flow.NoiseKey, &flow.Created, &flow.Expires)
	if errors.Is(err, sql.ErrNoRows) {
		return flow, errNativeFlow
	}
	return flow, err
}

func (registry *OrgRegistry) nativeFlow(ctx context.Context, id string) (nativeFlow, error) {
	return scanNativeFlow(registry.db.QueryRowContext(ctx, "SELECT "+nativeFlowColumns+" FROM native_device_flows WHERE id = ? AND expires_at > ?", id, time.Now().UnixNano()))
}

func (registry *OrgRegistry) nativeFlowByKeys(ctx context.Context, machine, node string) (nativeFlow, error) {
	return scanNativeFlow(registry.db.QueryRowContext(ctx, "SELECT "+nativeFlowColumns+" FROM native_device_flows WHERE machine_key = ? AND node_key = ? AND expires_at > ?", machine, node, time.Now().UnixNano()))
}

func (registry *OrgRegistry) createNativeFlow(ctx context.Context, machine key.MachinePublic, request tailcfg.RegisterRequest) (nativeFlow, error) {
	// 流程不保存 Auth Key、OAuth 或人类 Session；它只确定设备接入范围。
	request.Auth, request.Followup = nil, ""
	registration, err := json.Marshal(request)
	if err != nil || len(registration) > int(noiseBodyLimit) {
		return nativeFlow{}, errNativeFlow
	}
	transaction, err := registry.db.BeginTx(ctx, nil)
	if err != nil {
		return nativeFlow{}, err
	}
	defer transaction.Rollback()
	now := time.Now()
	if _, err := transaction.ExecContext(ctx, "DELETE FROM native_device_flows WHERE expires_at <= ?", now.UnixNano()); err != nil {
		return nativeFlow{}, err
	}
	flow, err := scanNativeFlow(transaction.QueryRowContext(ctx, "SELECT "+nativeFlowColumns+" FROM native_device_flows WHERE machine_key = ? AND node_key = ?", machine.String(), request.NodeKey.String()))
	if err == nil {
		return flow, transaction.Commit()
	}
	if !errors.Is(err, errNativeFlow) {
		return nativeFlow{}, err
	}
	var count int
	if err := transaction.QueryRowContext(ctx, "SELECT count(*) FROM native_device_flows").Scan(&count); err != nil {
		return nativeFlow{}, err
	}
	if count >= 256 {
		return nativeFlow{}, errNativeFlow
	}
	flow = nativeFlow{ID: newAuthID(), MachineKey: machine.String(), NodeKey: request.NodeKey.String(), Registration: string(registration), Created: now.UnixNano(), Expires: now.Add(registrationTTL).UnixNano()}
	if _, err := transaction.ExecContext(ctx, "INSERT INTO native_device_flows ("+nativeFlowColumns+") VALUES (?, ?, ?, ?, '', '', ?, ?)",
		flow.ID, flow.MachineKey, flow.NodeKey, flow.Registration, flow.Created, flow.Expires); err != nil {
		return nativeFlow{}, err
	}
	return flow, transaction.Commit()
}

func (registry *OrgRegistry) selectNativeFlow(ctx context.Context, id, organization, generation string) (nativeFlow, error) {
	transaction, err := registry.db.BeginTx(ctx, nil)
	if err != nil {
		return nativeFlow{}, err
	}
	defer transaction.Rollback()
	flow, err := scanNativeFlow(transaction.QueryRowContext(ctx, "SELECT "+nativeFlowColumns+" FROM native_device_flows WHERE id = ? AND expires_at > ?", id, time.Now().UnixNano()))
	if err != nil {
		return flow, err
	}
	if flow.Organization != "" && (flow.Organization != organization || flow.NoiseKey != generation) {
		return flow, errNativeScope
	}
	if err := bindNativeTx(ctx, transaction, flow.MachineKey, flow.NodeKey, organization, generation); err != nil {
		return flow, err
	}
	result, err := transaction.ExecContext(ctx, "UPDATE native_device_flows SET org_id = ?, noise_key = ? WHERE id = ?", organization, generation, id)
	if err != nil {
		return flow, err
	}
	if count, err := result.RowsAffected(); err != nil || count != 1 {
		return flow, errNativeFlow
	}
	flow.Organization, flow.NoiseKey = organization, generation
	return flow, transaction.Commit()
}

func (registry *OrgRegistry) nativeBindingsForMachine(ctx context.Context, machine string) ([]nativeBinding, error) {
	rows, err := registry.db.QueryContext(ctx, "SELECT machine_key, node_key, org_id, noise_key FROM native_device_bindings WHERE machine_key = ?", machine)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	bindings := make([]nativeBinding, 0)
	for rows.Next() {
		var binding nativeBinding
		if err := rows.Scan(&binding.MachineKey, &binding.NodeKey, &binding.Organization, &binding.NoiseKey); err != nil {
			return nil, err
		}
		bindings = append(bindings, binding)
	}
	return bindings, rows.Err()
}
