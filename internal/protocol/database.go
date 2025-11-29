package protocol

import (
	"bufio"
	"context"
	"net"
	"strings"
	"time"

	"github.com/nao1215/onionscan/internal/model"
	"golang.org/x/net/proxy"
)

// Database protocol name constants.
const (
	protocolMongoDB    = "mongodb"
	protocolRedis      = "redis"
	protocolPostgreSQL = "postgresql"
	protocolMySQL      = "mysql"
)

// MongoDBScanner performs MongoDB scanning on onion services.
// It connects to port 27017 to detect MongoDB servers.
//
// Design decision: Database scanners are included because:
//  1. Exposed databases are a significant security risk
//  2. Default configurations often have no authentication
//  3. Database banners reveal software versions
type MongoDBScanner struct {
	dialer  proxy.Dialer
	timeout time.Duration
}

// NewMongoDBScanner creates a new MongoDB scanner.
func NewMongoDBScanner(dialer proxy.Dialer) *MongoDBScanner {
	return &MongoDBScanner{
		dialer:  dialer,
		timeout: 30 * time.Second,
	}
}

// Protocol returns the protocol name.
func (s *MongoDBScanner) Protocol() string {
	return protocolMongoDB
}

// DefaultPort returns the default MongoDB port.
func (s *MongoDBScanner) DefaultPort() int {
	return 27017
}

// Scan performs a MongoDB scan on the target.
// MongoDB doesn't send a banner, so we detect it by connection success.
func (s *MongoDBScanner) Scan(ctx context.Context, target string) (*ScanResult, error) {
	result := NewScanResult(protocolMongoDB, 27017)

	host := normalizeHost(target, "27017")

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	conn, err := dialWithContext(ctx, s.dialer, host)
	if err != nil {
		return result, nil
	}
	defer conn.Close()

	result.Detected = true

	result.AddFinding(Finding{
		Title:       "MongoDB Server Detected",
		Description: "A MongoDB server is listening on port 27017. Ensure authentication is enabled and access is restricted.",
		Severity:    model.SeverityMedium,
		Location:    "Port 27017",
		Category:    "database",
	})

	return result, nil
}

// RedisScanner performs Redis scanning on onion services.
// It connects to port 6379 to detect Redis servers.
type RedisScanner struct {
	dialer  proxy.Dialer
	timeout time.Duration
}

// NewRedisScanner creates a new Redis scanner.
func NewRedisScanner(dialer proxy.Dialer) *RedisScanner {
	return &RedisScanner{
		dialer:  dialer,
		timeout: 30 * time.Second,
	}
}

// Protocol returns the protocol name.
func (s *RedisScanner) Protocol() string {
	return protocolRedis
}

// DefaultPort returns the default Redis port.
func (s *RedisScanner) DefaultPort() int {
	return 6379
}

// Scan performs a Redis scan on the target.
// Redis responds to PING with PONG when unauthenticated access is allowed.
func (s *RedisScanner) Scan(ctx context.Context, target string) (*ScanResult, error) {
	result := NewScanResult(protocolRedis, 6379)

	host := normalizeHost(target, "6379")

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	conn, err := dialWithContext(ctx, s.dialer, host)
	if err != nil {
		return result, nil
	}
	defer conn.Close()

	// Set deadline
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return result, nil
	}

	// Send PING command
	_, err = conn.Write([]byte("PING\r\n"))
	if err != nil {
		return result, nil
	}

	result.Detected = true

	// Read response
	reader := bufio.NewReader(conn)
	response, err := reader.ReadString('\n')
	if err == nil {
		response = strings.TrimSpace(response)
		result.Banner = response

		// Check for PONG response (unauthenticated access)
		if strings.Contains(strings.ToUpper(response), "PONG") {
			result.AddFinding(Finding{
				Title:       "Redis Server Allows Unauthenticated Access",
				Description: "Redis server responds to PING without authentication. This is a critical security issue as the database can be read and modified by anyone.",
				Severity:    model.SeverityCritical,
				Location:    "Port 6379",
				Category:    "database",
			})
		} else if strings.Contains(strings.ToUpper(response), "NOAUTH") ||
			strings.Contains(strings.ToUpper(response), "ERR") {
			result.AddFinding(Finding{
				Title:       "Redis Server Detected (Authentication Required)",
				Description: "Redis server is running with authentication enabled.",
				Severity:    model.SeverityInfo,
				Location:    "Port 6379",
				Category:    "database",
			})
		}
	}

	return result, nil
}

// PostgreSQLScanner performs PostgreSQL scanning on onion services.
// It connects to port 5432 to detect PostgreSQL servers.
type PostgreSQLScanner struct {
	dialer  proxy.Dialer
	timeout time.Duration
}

// NewPostgreSQLScanner creates a new PostgreSQL scanner.
func NewPostgreSQLScanner(dialer proxy.Dialer) *PostgreSQLScanner {
	return &PostgreSQLScanner{
		dialer:  dialer,
		timeout: 30 * time.Second,
	}
}

// Protocol returns the protocol name.
func (s *PostgreSQLScanner) Protocol() string {
	return protocolPostgreSQL
}

// DefaultPort returns the default PostgreSQL port.
func (s *PostgreSQLScanner) DefaultPort() int {
	return 5432
}

// Scan performs a PostgreSQL scan on the target.
func (s *PostgreSQLScanner) Scan(ctx context.Context, target string) (*ScanResult, error) {
	result := NewScanResult(protocolPostgreSQL, 5432)

	host := normalizeHost(target, "5432")

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	conn, err := dialWithContext(ctx, s.dialer, host)
	if err != nil {
		return result, nil
	}
	defer conn.Close()

	result.Detected = true

	result.AddFinding(Finding{
		Title:       "PostgreSQL Server Detected",
		Description: "A PostgreSQL server is listening on port 5432. Ensure authentication is properly configured.",
		Severity:    model.SeverityMedium,
		Location:    "Port 5432",
		Category:    "database",
	})

	return result, nil
}

// MySQLScanner performs MySQL scanning on onion services.
// It connects to port 3306 to detect MySQL/MariaDB servers.
type MySQLScanner struct {
	dialer  proxy.Dialer
	timeout time.Duration
}

// NewMySQLScanner creates a new MySQL scanner.
func NewMySQLScanner(dialer proxy.Dialer) *MySQLScanner {
	return &MySQLScanner{
		dialer:  dialer,
		timeout: 30 * time.Second,
	}
}

// Protocol returns the protocol name.
func (s *MySQLScanner) Protocol() string {
	return protocolMySQL
}

// DefaultPort returns the default MySQL port.
func (s *MySQLScanner) DefaultPort() int {
	return 3306
}

// Scan performs a MySQL scan on the target.
// MySQL servers send a greeting packet upon connection.
func (s *MySQLScanner) Scan(ctx context.Context, target string) (*ScanResult, error) {
	result := NewScanResult(protocolMySQL, 3306)

	host := normalizeHost(target, "3306")

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	conn, err := dialWithContext(ctx, s.dialer, host)
	if err != nil {
		return result, nil
	}
	defer conn.Close()

	// Set read deadline
	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return result, nil
	}

	result.Detected = true

	// MySQL sends a handshake packet
	// We read raw bytes to check for MySQL signature
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		result.AddFinding(Finding{
			Title:       "MySQL/MariaDB Server Detected",
			Description: "A MySQL or MariaDB server is listening on port 3306.",
			Severity:    model.SeverityMedium,
			Location:    "Port 3306",
			Category:    "database",
		})
		return result, nil
	}

	// Parse MySQL greeting for version
	if n > 5 {
		// MySQL handshake: [length(3)][packet_number(1)][protocol_version(1)][version(null-terminated)]
		greeting := buf[:n]

		// Check if we have enough data
		if len(greeting) > 5 && greeting[4] == 10 { // protocol version 10
			// Extract version string (null-terminated after packet header)
			versionBytes := greeting[5:]
			for i, b := range versionBytes {
				if b == 0 {
					versionBytes = versionBytes[:i]
					break
				}
			}
			version := string(versionBytes)
			result.Banner = version

			// Check for MariaDB vs MySQL
			if strings.Contains(strings.ToLower(version), "mariadb") {
				result.SetMetadata("database_type", "MariaDB")
			} else {
				result.SetMetadata("database_type", "MySQL")
			}

			result.AddFinding(Finding{
				Title:       "MySQL/MariaDB Version Disclosed",
				Description: "The database server discloses its version in the handshake.",
				Severity:    model.SeverityLow,
				Value:       version,
				Location:    "Port 3306 Handshake",
				Category:    "database",
			})
		}
	}

	return result, nil
}

// normalizeHost normalizes a host string by stripping protocol prefixes
// and adding a default port if not present.
//
// This is a helper function shared by database scanners.
func normalizeHost(target, defaultPort string) string {
	host := target

	// Strip common protocol prefixes
	for _, prefix := range []string{"mongodb://", "redis://", "postgresql://", "postgres://", "mysql://"} {
		if strings.HasPrefix(host, prefix) {
			host = strings.TrimPrefix(host, prefix)
			break
		}
	}

	// Remove credentials if present (user:pass@host)
	if idx := strings.LastIndex(host, "@"); idx != -1 {
		host = host[idx+1:]
	}

	// Remove path
	if idx := strings.Index(host, "/"); idx != -1 {
		host = host[:idx]
	}

	// Remove query parameters
	if idx := strings.Index(host, "?"); idx != -1 {
		host = host[:idx]
	}

	// Add default port if not present
	if !strings.Contains(host, ":") {
		host = host + ":" + defaultPort
	}

	return host
}

// dialWithContext dials a TCP connection respecting context cancellation.
// This is a shared helper function for all protocol scanners.
func dialWithContext(ctx context.Context, dialer proxy.Dialer, address string) (net.Conn, error) {
	type dialResult struct {
		conn net.Conn
		err  error
	}

	resultCh := make(chan dialResult, 1)

	go func() {
		conn, err := dialer.Dial("tcp", address)
		resultCh <- dialResult{conn, err}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case result := <-resultCh:
		return result.conn, result.err
	}
}
