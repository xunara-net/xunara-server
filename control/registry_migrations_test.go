package control

import (
	"database/sql"
	"path/filepath"
	"sync"
	"testing"
)

func migrationDatabase(test *testing.T, filename string) *sql.DB {
	test.Helper()
	database, err := sql.Open("sqlite", "file:"+filename+"?_txlock=immediate&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		test.Fatal(err)
	}
	database.SetMaxOpenConns(1)
	test.Cleanup(func() { database.Close() })
	// 先完成连接初始化与 WAL 切换，下面并发测试只竞争迁移事务而非首次建库。
	if err := database.PingContext(test.Context()); err != nil {
		test.Fatal(err)
	}
	return database
}

func TestRegistryMigrationFailureRollsBackDDLAndVersion(test *testing.T) {
	database := migrationDatabase(test, filepath.Join(test.TempDir(), "registry.db"))
	first := "CREATE TABLE example (id INTEGER PRIMARY KEY)"
	broken := "ALTER TABLE example ADD COLUMN extra TEXT; INSERT INTO absent_table VALUES (1)"
	if err := migrateRegistry(test.Context(), database, []string{first, broken}, "fixture"); err == nil {
		test.Fatal("incomplete migration succeeded")
	}
	var version, columns int
	if err := database.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		test.Fatal(err)
	}
	if err := database.QueryRow("SELECT count(*) FROM pragma_table_info('example') WHERE name = 'extra'").Scan(&columns); err != nil {
		test.Fatal(err)
	}
	if version != 1 || columns != 0 {
		test.Fatal("partial DDL or version persisted")
	}
	if err := migrateRegistry(test.Context(), database, []string{first, "ALTER TABLE example ADD COLUMN extra TEXT"}, "fixture"); err != nil {
		test.Fatal(err)
	}
}

func TestRegistryMigrationAcrossConnectionsDoesNotRepeatDDL(test *testing.T) {
	filename := filepath.Join(test.TempDir(), "registry.db")
	connections := []*sql.DB{migrationDatabase(test, filename), migrationDatabase(test, filename)}
	migrations := []string{"CREATE TABLE example (id INTEGER)", "ALTER TABLE example ADD COLUMN extra TEXT"}
	start := make(chan struct{})
	results := make(chan error, len(connections))
	var workers sync.WaitGroup
	for _, database := range connections {
		workers.Go(func() { <-start; results <- migrateRegistry(test.Context(), database, migrations, "fixture") })
	}
	close(start)
	workers.Wait()
	close(results)
	for err := range results {
		if err != nil {
			test.Fatal(err)
		}
	}
}
