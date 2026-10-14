package control

import (
	"context"
	"database/sql"
	"fmt"
)

// 版本与全部 DDL 同提交；版本在写锁内读取，避免两个启动实例重复应用迁移。
func migrateRegistry(ctx context.Context, database *sql.DB, migrations []string, name string) error {
	for {
		transaction, err := database.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("control: starting %s migration: %w", name, err)
		}
		var version int
		if err := transaction.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
			transaction.Rollback()
			return fmt.Errorf("control: reading %s schema version: %w", name, err)
		}
		if version < 0 || version > len(migrations) {
			transaction.Rollback()
			return fmt.Errorf("control: %s schema version %d is unsupported", name, version)
		}
		if version == len(migrations) {
			return transaction.Rollback()
		}
		if _, err := transaction.ExecContext(ctx, migrations[version]); err != nil {
			transaction.Rollback()
			return fmt.Errorf("control: applying %s migration %d: %w", name, version+1, err)
		}
		if _, err := transaction.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", version+1)); err != nil {
			transaction.Rollback()
			return fmt.Errorf("control: recording %s migration %d: %w", name, version+1, err)
		}
		if err := transaction.Commit(); err != nil {
			return fmt.Errorf("control: committing %s migration %d: %w", name, version+1, err)
		}
	}
}
