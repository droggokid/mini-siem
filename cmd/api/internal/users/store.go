package users

import (
	"context"
	"database/sql"
	_ "embed"
	"fmt"

	sq "github.com/Masterminds/squirrel"
	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var schema string

type userRow struct {
	ID           int64  `db:"id"`
	Username     string `db:"username"`
	PasswordHash []byte `db:"password_hash"`
	Role         string `db:"role"`
}

type Store struct {
	db   *sql.DB
	psql sq.StatementBuilderType
}

// Open creates the users table and seeds any missing demo accounts.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open users database: %w", err)
	}
	db.SetMaxOpenConns(1)
	store := &Store{
		db:   db,
		psql: sq.StatementBuilder.PlaceholderFormat(sq.Dollar).RunWith(db),
	}
	if err = store.initialize(); err != nil {
		db.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) initialize() error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin users initialization: %w", err)
	}
	defer tx.Rollback()
	psql := s.psql.RunWith(tx)

	if _, err = tx.Exec(schema); err != nil {
		return fmt.Errorf("create users table: %w", err)
	}

	for _, seed := range []struct{ username, password, role string }{
		{"Alice", "alice-password", "user"},
		{"Bob", "bob-password", "user"},
		{"Admin", "admin-password", "admin"},
	} {
		var hash []byte
		hash, err = bcrypt.GenerateFromPassword([]byte(seed.password), bcrypt.DefaultCost)
		if err != nil {
			return fmt.Errorf("hash seed password: %w", err)
		}
		if _, err = psql.Insert("users").
			Columns("username", "password_hash", "role").
			Values(seed.username, hash, seed.role).
			Suffix("ON CONFLICT(username) DO NOTHING").Exec(); err != nil {
			return fmt.Errorf("seed users: %w", err)
		}
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("commit users initialization: %w", err)
	}
	return nil
}

// LookupByUsername returns sql.ErrNoRows when the username does not exist.
func (s *Store) LookupByUsername(ctx context.Context, username string) (User, error) {
	var row userRow
	err := s.psql.Select("id", "username", "password_hash", "role").
		From("users").
		Where(sq.Eq{"username": username}).
		QueryRowContext(ctx).
		Scan(&row.ID, &row.Username, &row.PasswordHash, &row.Role)
	if err != nil {
		return User{}, fmt.Errorf("look up user: %w", err)
	}
	return User{ID: row.ID, Username: row.Username, Role: row.Role}, nil
}
