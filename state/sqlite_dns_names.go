package state

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

type dnsQuery interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func dnsFacts(ctx context.Context, query dnsQuery, hasAssignedNames bool) ([]Node, []Service, []DNSRecord, error) {
	nameColumn := "dns_name"
	if !hasAssignedNames {
		nameColumn = "''"
	}
	rows, err := query.QueryContext(ctx, "SELECT id, hostname, "+nameColumn+" FROM nodes ORDER BY id")
	if err != nil {
		return nil, nil, nil, err
	}
	var nodes []Node
	for rows.Next() {
		var node Node
		if err := rows.Scan(&node.ID, &node.Hostname, &node.DNSName); err != nil {
			rows.Close()
			return nil, nil, nil, err
		}
		nodes = append(nodes, node)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, nil, nil, err
	}
	rows, err = query.QueryContext(ctx, "SELECT node_id, name FROM node_services")
	if err != nil {
		return nil, nil, nil, err
	}
	var services []Service
	for rows.Next() {
		var service Service
		if err := rows.Scan(&service.NodeID, &service.Name); err != nil {
			rows.Close()
			return nil, nil, nil, err
		}
		services = append(services, service)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, nil, nil, err
	}
	rows, err = query.QueryContext(ctx, "SELECT name FROM dns_records")
	if err != nil {
		return nil, nil, nil, err
	}
	var records []DNSRecord
	for rows.Next() {
		var record DNSRecord
		if err := rows.Scan(&record.Name); err != nil {
			rows.Close()
			return nil, nil, nil, err
		}
		records = append(records, record)
	}
	err = rows.Err()
	rows.Close()
	return nodes, services, records, err
}

func dnsDomainTx(ctx context.Context, transaction *sql.Tx) (string, bool, error) {
	var domain string
	err := transaction.QueryRowContext(ctx, "SELECT domain FROM dns_namespace WHERE id = 1").Scan(&domain)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err == nil {
		canonical, validationErr := NormalizeDNSDomain(domain)
		if validationErr != nil || canonical != domain || domain == "" {
			return "", false, fmt.Errorf("state: malformed persisted DNS namespace")
		}
	}
	return domain, err == nil, err
}

func dnsNameOwnersTx(ctx context.Context, transaction *sql.Tx, domain string, excludeNode, excludeServices NodeID) (map[string]string, error) {
	nodes, services, records, err := dnsFacts(ctx, transaction, true)
	if err != nil {
		return nil, err
	}
	return dnsNameOwners(nodes, services, records, domain, excludeNode, excludeServices)
}

func (store *SQLiteStore) ConfigureDNSDomain(ctx context.Context, domain string) error {
	domain, err := NormalizeDNSDomain(domain)
	if err != nil {
		return err
	}
	transaction, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	previous, bound, err := dnsDomainTx(ctx, transaction)
	if err != nil {
		return err
	}
	if bound && previous != domain {
		return ErrDNSDomainChange
	}
	nodes, services, records, err := dnsFacts(ctx, transaction, true)
	if err != nil {
		return err
	}
	if _, err := dnsNameOwners(nodes, services, records, domain, 0, 0); err != nil {
		return err
	}
	// 验证全部完成才补录，不能在升级中悄悄给旧设备换名。
	for _, node := range nodes {
		if node.DNSName == "" {
			if _, err := transaction.ExecContext(ctx, "UPDATE nodes SET dns_name = ? WHERE id = ?", defaultDNSLabel(node), int64(node.ID)); err != nil {
				return err
			}
		}
	}
	if !bound && domain != "" {
		if _, err := transaction.ExecContext(ctx, "INSERT INTO dns_namespace (id, domain) VALUES (1, ?)", domain); err != nil {
			return err
		}
	}
	return transaction.Commit()
}

// CheckDNSRecordNameTx 与记录写入共用事务，保护设备和服务的名称归属。
func CheckDNSRecordNameTx(ctx context.Context, transaction *sql.Tx, name, domain string) error {
	actual, bound, err := dnsDomainTx(ctx, transaction)
	if err != nil {
		return err
	}
	if bound && actual != domain {
		return ErrDNSDomainChange
	}
	owners, err := dnsNameOwnersTx(ctx, transaction, domain, 0, 0)
	if err != nil {
		return err
	}
	return checkRecordDNSName(name, domain, owners)
}

func checkServiceDNSNamesTx(ctx context.Context, transaction *sql.Tx, id NodeID, services []Service) error {
	domain, _, err := dnsDomainTx(ctx, transaction)
	if err != nil {
		return err
	}
	owners, err := dnsNameOwnersTx(ctx, transaction, domain, 0, id)
	if err != nil {
		return err
	}
	for _, service := range services {
		name := strings.ToLower(service.Name)
		if _, taken := owners[name]; taken {
			return errServiceNameTaken(service.Name)
		}
		owners[name] = "pending-service"
	}
	return nil
}

// CheckDNSNamespace 只读检查升级前归属，不应用迁移、不改写 WAL 配置或设备状态。
func CheckDNSNamespace(ctx context.Context, path, domain string) error {
	if strings.ContainsAny(path, "?#") {
		return fmt.Errorf("state: unsupported character in database path")
	}
	domain, err := NormalizeDNSDomain(domain)
	if err != nil {
		return err
	}
	database, err := sql.Open("sqlite", "file:"+path+"?mode=ro&_pragma=busy_timeout(5000)")
	if err != nil {
		return err
	}
	defer database.Close()
	database.SetMaxOpenConns(1)
	transaction, err := database.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	var hasAssignedNames bool
	if err := transaction.QueryRowContext(ctx, "SELECT count(*) > 0 FROM pragma_table_info('nodes') WHERE name = 'dns_name'").Scan(&hasAssignedNames); err != nil {
		return err
	}
	if hasAssignedNames {
		previous, bound, err := dnsDomainTx(ctx, transaction)
		if err != nil {
			return err
		}
		if bound && previous != domain {
			return ErrDNSDomainChange
		}
	}
	nodes, services, records, err := dnsFacts(ctx, transaction, hasAssignedNames)
	if err != nil {
		return err
	}
	_, err = dnsNameOwners(nodes, services, records, domain, 0, 0)
	return err
}
