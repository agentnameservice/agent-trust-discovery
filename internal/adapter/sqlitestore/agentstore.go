package sqlitestore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/agentnameservice/agent-trust-discovery/internal/domain"
)

// agentColumns is the canonical agent column list/order, shared by GetAgent and
// the search query so scanAgent reads a single, stable layout. Columns are
// table-qualified so the SELECT is unambiguous when joined to agents_fts (which
// shares column names like agent_id/dns_name).
const agentColumns = "agents.agent_id, agents.dns_name, agents.display_name, agents.description, " +
	"agents.provider_id, agents.status, agents.protocols, agents.transports, agents.tags, " +
	"agents.capabilities, agents.first_seen, agents.last_updated"

// rowScanner is satisfied by both *sql.Row and *sql.Rows.
type rowScanner interface {
	Scan(dest ...any) error
}

// UpsertAgents applies UpsertAgent to every entry inside a single transaction.
// Any per-row failure rolls the entire batch back so the caller never observes
// a partial commit.
func (d *DB) UpsertAgents(ctx context.Context, agents []domain.Agent) error {
	if len(agents) == 0 {
		return nil
	}
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("sqlitestore: begin upsert agents tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	for _, a := range agents {
		if err := upsertAgentTx(ctx, tx, a); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("sqlitestore: commit upsert agents tx: %w", err)
	}
	return nil
}

// AppendObservations applies AppendObservation to every entry inside a single
// transaction with the same all-or-nothing semantics.
func (d *DB) AppendObservations(ctx context.Context, obs []domain.SignalObservation) error {
	if len(obs) == 0 {
		return nil
	}
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("sqlitestore: begin append observations tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	for _, o := range obs {
		if err := appendObservationTx(ctx, tx, o); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("sqlitestore: commit append observations tx: %w", err)
	}
	return nil
}

// upsertAgentTx is the row-level body shared by UpsertAgent and UpsertAgents;
// the sql.Tx and *sql.DB both satisfy the ExecContext contract via execer.
func upsertAgentTx(ctx context.Context, ex execer, a domain.Agent) error {
	protocols, err := marshalStrings(a.Protocols)
	if err != nil {
		return err
	}
	transports, err := marshalStrings(a.Transports)
	if err != nil {
		return err
	}
	tags, err := marshalStrings(a.Tags)
	if err != nil {
		return err
	}
	capabilities, err := marshalStrings(a.Capabilities)
	if err != nil {
		return err
	}
	const q = `
INSERT INTO agents (agent_id, dns_name, display_name, description, provider_id, status,
                    protocols, transports, tags, capabilities, first_seen, last_updated)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(agent_id) DO UPDATE SET
    dns_name     = excluded.dns_name,
    display_name = excluded.display_name,
    description  = excluded.description,
    provider_id  = excluded.provider_id,
    status       = excluded.status,
    protocols    = excluded.protocols,
    transports   = excluded.transports,
    tags         = excluded.tags,
    capabilities = excluded.capabilities,
    first_seen   = excluded.first_seen,
    last_updated = excluded.last_updated`
	if _, err := ex.ExecContext(ctx, q,
		string(a.ID), a.DNSName, a.DisplayName, a.Description, a.ProviderID, string(a.Status),
		protocols, transports, tags, capabilities,
		formatTime(a.FirstSeen), formatTime(a.LastUpdated),
	); err != nil {
		return fmt.Errorf("sqlitestore: upsert agent %s: %w", a.ID, err)
	}
	return nil
}

func appendObservationTx(ctx context.Context, ex execer, obs domain.SignalObservation) error {
	prov, err := marshalProvenance(obs.Provenance)
	if err != nil {
		return err
	}
	const q = `INSERT INTO signal_observations (agent_id, signal_id, observed_at, value_json, provenance_json)
               VALUES (?, ?, ?, ?, ?)
               ON CONFLICT(agent_id, signal_id, observed_at) DO NOTHING`
	if _, err := ex.ExecContext(ctx, q,
		string(obs.AgentID), string(obs.SignalID), formatTime(obs.ObservedAt), string(obs.Value), prov,
	); err != nil {
		return fmt.Errorf("sqlitestore: append observation (%s, %s): %w", obs.AgentID, obs.SignalID, err)
	}
	return nil
}

// execer abstracts sql.DB and sql.Tx so the row-level bodies above share code.
type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// UpsertAgent inserts or replaces the agent keyed on its ID. The agents_ai/au
// triggers keep the FTS index in lockstep (design §7).
func (d *DB) UpsertAgent(ctx context.Context, a domain.Agent) error {
	return upsertAgentTx(ctx, d.db, a)
}

// GetAgent returns the agent and true, or the zero agent and false when absent.
func (d *DB) GetAgent(ctx context.Context, id domain.AgentID) (domain.Agent, bool, error) {
	row := d.db.QueryRowContext(ctx, "SELECT "+agentColumns+" FROM agents WHERE agent_id = ?", string(id))
	a, err := scanAgent(row)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Agent{}, false, nil
	}
	if err != nil {
		return domain.Agent{}, false, fmt.Errorf("sqlitestore: get agent %s: %w", id, err)
	}
	return a, true, nil
}

// AppendObservation records a new observation row. A duplicate row (same
// agent, same signal, same observed_at) is a no-op — the migration
// 0002_observations_dedup.sql adds a UNIQUE index on that triple and the
// INSERT uses ON CONFLICT DO NOTHING. That keeps retries and cadence-loop
// re-imports idempotent without changing the scoring-engine view (which
// always reads the newest row).
func (d *DB) AppendObservation(ctx context.Context, obs domain.SignalObservation) error {
	return appendObservationTx(ctx, d.db, obs)
}

// PruneObservations trims the observation history to the newest keepPerPair
// rows per (agent_id, signal_id). The scoring engine only ever reads the
// most-recent row via LatestObservation, so older rows are pure storage
// overhead; this bounds long-term growth for deployments where a prober
// runs on a cadence.
//
// keepPerPair ≤ 0 is a no-op (retention disabled). Returns the number of
// rows deleted.
func (d *DB) PruneObservations(ctx context.Context, keepPerPair int) (int64, error) {
	if keepPerPair <= 0 {
		return 0, nil
	}
	// For each (agent_id, signal_id) group, keep the K rows with the largest
	// (observed_at, obs_id) tuple — same ordering as LatestObservation, so we
	// never delete the row the engine would read.
	const q = `
DELETE FROM signal_observations
WHERE obs_id IN (
    SELECT obs_id FROM (
        SELECT obs_id,
               ROW_NUMBER() OVER (
                   PARTITION BY agent_id, signal_id
                   ORDER BY observed_at DESC, obs_id DESC
               ) AS rn
        FROM signal_observations
    )
    WHERE rn > ?
)`
	res, err := d.db.ExecContext(ctx, q, keepPerPair)
	if err != nil {
		return 0, fmt.Errorf("sqlitestore: prune observations: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("sqlitestore: prune observations rows affected: %w", err)
	}
	return n, nil
}

// LatestObservation returns the most recent observation for the pair, or nil
// when none has been recorded (design §4.1: a valid input to Signal.Evaluate).
func (d *DB) LatestObservation(ctx context.Context, agentID domain.AgentID, signalID domain.SignalID) (*domain.SignalObservation, error) {
	const q = `SELECT agent_id, signal_id, observed_at, value_json, provenance_json
               FROM signal_observations
               WHERE agent_id = ? AND signal_id = ?
               ORDER BY observed_at DESC, obs_id DESC
               LIMIT 1`
	var (
		aid, sid, observedAt, valueJSON string
		prov                            sql.NullString
	)
	err := d.db.QueryRowContext(ctx, q, string(agentID), string(signalID)).
		Scan(&aid, &sid, &observedAt, &valueJSON, &prov)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil //nolint:nilnil // nil obs + nil err means "none recorded" (port contract)
	}
	if err != nil {
		return nil, fmt.Errorf("sqlitestore: latest observation (%s, %s): %w", agentID, signalID, err)
	}

	observed, err := parseTime(observedAt)
	if err != nil {
		return nil, err
	}
	p, err := unmarshalProvenance(prov)
	if err != nil {
		return nil, err
	}
	return &domain.SignalObservation{
		AgentID:    domain.AgentID(aid),
		SignalID:   domain.SignalID(sid),
		ObservedAt: observed,
		Value:      json.RawMessage(valueJSON),
		Provenance: p,
	}, nil
}

func scanAgent(s rowScanner) (domain.Agent, error) {
	var (
		a                                         domain.Agent
		id, status                                string
		protocols, transports, tags, capabilities string
		firstSeen, lastUpdated                    string
	)
	if err := s.Scan(&id, &a.DNSName, &a.DisplayName, &a.Description, &a.ProviderID, &status,
		&protocols, &transports, &tags, &capabilities, &firstSeen, &lastUpdated); err != nil {
		return domain.Agent{}, err
	}
	a.ID = domain.AgentID(id)
	a.Status = domain.Status(status)

	var err error
	if a.Protocols, err = unmarshalStrings(protocols); err != nil {
		return domain.Agent{}, err
	}
	if a.Transports, err = unmarshalStrings(transports); err != nil {
		return domain.Agent{}, err
	}
	if a.Tags, err = unmarshalStrings(tags); err != nil {
		return domain.Agent{}, err
	}
	if a.Capabilities, err = unmarshalStrings(capabilities); err != nil {
		return domain.Agent{}, err
	}
	if a.FirstSeen, err = parseTime(firstSeen); err != nil {
		return domain.Agent{}, err
	}
	if a.LastUpdated, err = parseTime(lastUpdated); err != nil {
		return domain.Agent{}, err
	}
	return a, nil
}
