package sqlite

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const sealFile = "device-seal.key"
const sealPrefix = "enc:v1:"

func readSeal(path string, create bool) ([]byte, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) && create {
		key := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, key); err != nil {
			return nil, err
		}
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return nil, err
		}
		if _, err := f.Write(key); err != nil {
			f.Close()
			os.Remove(path)
			return nil, err
		}
		if err := f.Close(); err != nil {
			os.Remove(path)
			return nil, err
		}
		return key, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("device seal file must be regular and owner-only")
	}
	key, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(key) != 32 {
		return nil, errors.New("device seal file has invalid length")
	}
	return key, nil
}

func sealCheck(key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("Weroxy credential seal v1"))
	return mac.Sum(nil)
}

func (db *DB) initSeal(ctx context.Context) error {
	var saved []byte
	err := db.write.QueryRowContext(ctx, `SELECT seal_check FROM credential_store WHERE id = 1`).Scan(&saved)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	key, err := readSeal(filepath.Join(filepath.Dir(db.path), sealFile), errors.Is(err, sql.ErrNoRows))
	if err != nil {
		return fmt.Errorf("device seal unavailable: %w", err)
	}
	if len(saved) != 0 && subtle.ConstantTimeCompare(saved, sealCheck(key)) != 1 {
		return errors.New("device seal does not match this database")
	}
	db.seal = key
	if len(saved) != 0 {
		return nil
	}
	return db.upgradeCredentials(ctx)
}

func (db *DB) upgradeCredentials(ctx context.Context) error {
	tx, err := db.write.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, table := range []string{"legacy_devices", "weroxy_devices"} {
		rows, err := tx.QueryContext(ctx, `SELECT id, name, client_key FROM `+table+` WHERE client_key <> ''`)
		if err != nil {
			return err
		}
		type item struct {
			id          int64
			name, value string
		}
		var items []item
		for rows.Next() {
			var v item
			if err := rows.Scan(&v.id, &v.name, &v.value); err != nil {
				rows.Close()
				return err
			}
			items = append(items, v)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
		for _, v := range items {
			encoded, err := db.sealKey(v.name, v.value)
			if err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `UPDATE `+table+` SET client_key = ? WHERE id = ?`, encoded, v.id); err != nil {
				return err
			}
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO credential_store(id, seal_check) VALUES (1, ?)`, sealCheck(db.seal)); err != nil {
		return err
	}
	return tx.Commit()
}

func (db *DB) sealKey(name, value string) (string, error) {
	plain := []byte(value)
	defer func() {
		for i := range plain {
			plain[i] = 0
		}
	}()
	return db.sealKeyBytes(name, plain)
}

func (db *DB) sealKeyBytes(name string, value []byte) (string, error) {
	if len(value) == 0 {
		return "", nil
	}
	block, err := aes.NewCipher(db.seal)
	if err != nil {
		return "", err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	cipherText := aead.Seal(nonce, nonce, value, []byte(name))
	return sealPrefix + base64.RawURLEncoding.EncodeToString(cipherText), nil
}

func (db *DB) openKey(name, encoded string) (string, error) {
	if encoded == "" {
		return "", nil
	}
	if !strings.HasPrefix(encoded, sealPrefix) {
		return "", errors.New("unencrypted device credential")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(encoded, sealPrefix))
	if err != nil {
		return "", errors.New("invalid device credential")
	}
	block, err := aes.NewCipher(db.seal)
	if err != nil {
		return "", err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(raw) < aead.NonceSize() {
		return "", errors.New("invalid device credential")
	}
	plain, err := aead.Open(nil, raw[:aead.NonceSize()], raw[aead.NonceSize():], []byte(name))
	if err != nil {
		return "", errors.New("invalid device credential")
	}
	return string(plain), nil
}
