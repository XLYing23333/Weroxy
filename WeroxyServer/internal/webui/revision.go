package webui

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"weroxy/server/internal/storage/sqlite"
)

func (a *api) revisions(r *http.Request) (map[string]sqlite.Revision, error) {
	rows, err := a.db.ConfigRevisions(r.Context())
	if err != nil {
		return nil, err
	}
	out := make(map[string]sqlite.Revision, len(rows))
	for _, row := range rows {
		out[row.Domain] = row
	}
	return out, nil
}

func (a *api) configRevisions(w http.ResponseWriter, r *http.Request) {
	rows, err := a.revisions(r)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "invalid")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"revisions": rows})
}

func (a *api) mutateConfig(w http.ResponseWriter, r *http.Request, domain string, operationRequired bool, requestBody any, fn func(context.Context) error) (sqlite.MutationResult, bool) {
	raw := strings.TrimSpace(r.Header.Get("X-Expected-Revision"))
	if raw == "" {
		a.auditConfigFailure(r, domain, "expected_revision_required")
		writeError(w, http.StatusPreconditionRequired, "expected_revision_required")
		return sqlite.MutationResult{}, false
	}
	expected, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || expected < 0 {
		a.auditConfigFailure(r, domain, "invalid_revision")
		writeError(w, http.StatusBadRequest, "invalid_revision")
		return sqlite.MutationResult{}, false
	}
	opID := r.Header.Get("Idempotency-Key")
	if operationRequired && opID == "" {
		a.auditConfigFailure(r, domain, "operation_id_required")
		writeError(w, http.StatusBadRequest, "operation_id_required")
		return sqlite.MutationResult{}, false
	}
	encoded, err := json.Marshal(requestBody)
	if err != nil {
		a.auditConfigFailure(r, domain, "request_encoding")
		writeError(w, http.StatusBadRequest, "invalid")
		return sqlite.MutationResult{}, false
	}
	digest := sha256.Sum256(append([]byte(r.Method+"\n"+r.URL.Path+"\n"), encoded...))
	result, err := a.db.MutateConfig(r.Context(), domain, expected, opID, hex.EncodeToString(digest[:]), fn)
	if err != nil {
		reason := "write_failed"
		switch {
		case errors.Is(err, sqlite.ErrRevisionConflict):
			reason = "revision_conflict"
		case errors.Is(err, sqlite.ErrOperationID):
			reason = "operation_conflict"
		case errors.Is(err, sqlite.ErrConfigDomain):
			reason = "invalid_domain"
		}
		a.auditConfigFailure(r, domain, reason)
		writeMutationError(w, err)
		return sqlite.MutationResult{}, false
	}
	return result, true
}

// Failed mutations have rolled back before this independent, bounded audit attempt.
// Never include the request body, credential, operation ID or database error text.
func (a *api) auditConfigFailure(r *http.Request, domain, reason string) {
	ctx, cancel := context.WithTimeout(r.Context(), time.Second)
	defer cancel()
	_ = a.db.RecordAudit(ctx, "config_write", "failure", "domain="+domain+" reason="+reason)
}

func writeMutationError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, sqlite.ErrRevisionConflict):
		writeError(w, http.StatusConflict, "revision_conflict")
	case errors.Is(err, sqlite.ErrOperationID), errors.Is(err, sqlite.ErrConfigDomain):
		writeError(w, http.StatusBadRequest, "invalid")
	default:
		writeStore(w, err)
	}
}

func mutationBody(result sqlite.MutationResult, body map[string]any) map[string]any {
	body["domain"] = result.Domain
	body["desired_revision"] = result.DesiredRevision
	body["applied_revision"] = result.AppliedRevision
	body["failure_reason"] = result.FailureReason
	body["duplicate"] = result.Duplicate
	if result.DesiredRevision == result.AppliedRevision {
		body["status"] = "applied"
	} else {
		body["status"] = "saved"
	}
	return body
}
