-- Initial schema (design §7). Canonical agent record, append-only observation
-- history, and an FTS5 search index kept in lockstep with agents via triggers.

CREATE TABLE agents (
    agent_id      TEXT PRIMARY KEY,
    dns_name      TEXT NOT NULL,
    display_name  TEXT NOT NULL,
    description   TEXT NOT NULL DEFAULT '',
    provider_id   TEXT NOT NULL DEFAULT '',
    status        TEXT NOT NULL CHECK (status IN ('ACTIVE','WARNING','DEPRECATED','EXPIRED','REVOKED')),
    protocols     TEXT NOT NULL DEFAULT '[]',  -- JSON array
    transports    TEXT NOT NULL DEFAULT '[]',  -- JSON array
    tags          TEXT NOT NULL DEFAULT '[]',  -- JSON array
    capabilities  TEXT NOT NULL DEFAULT '[]',  -- JSON array
    first_seen    TEXT NOT NULL,               -- RFC 3339
    last_updated  TEXT NOT NULL                -- RFC 3339
);

-- Signal observation history. Append-only; the latest per (agent, signal) is
-- the row the scoring engine reads.
CREATE TABLE signal_observations (
    obs_id          INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id        TEXT NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    signal_id       TEXT NOT NULL,
    observed_at     TEXT NOT NULL,                -- RFC 3339
    value_json      TEXT NOT NULL,                -- per-signal payload, JSON
    provenance_json TEXT                          -- optional {aimId, evidenceUrl}; NULL when omitted
);

CREATE INDEX idx_obs_agent_signal_time
    ON signal_observations (agent_id, signal_id, observed_at DESC);

-- FTS5 virtual table for the search index. Synced via triggers.
CREATE VIRTUAL TABLE agents_fts USING fts5(
    agent_id UNINDEXED,
    dns_name,
    display_name,
    description,
    tags,
    capabilities,
    tokenize = 'porter unicode61'
);

-- Sync triggers: keep agents_fts in lockstep with agents.
CREATE TRIGGER agents_ai AFTER INSERT ON agents BEGIN
    INSERT INTO agents_fts (agent_id, dns_name, display_name, description, tags, capabilities)
    VALUES (new.agent_id, new.dns_name, new.display_name, new.description,
            new.tags, new.capabilities);
END;

CREATE TRIGGER agents_au AFTER UPDATE ON agents BEGIN
    UPDATE agents_fts
       SET dns_name     = new.dns_name,
           display_name = new.display_name,
           description  = new.description,
           tags         = new.tags,
           capabilities = new.capabilities
     WHERE agent_id = new.agent_id;
END;

CREATE TRIGGER agents_ad AFTER DELETE ON agents BEGIN
    DELETE FROM agents_fts WHERE agent_id = old.agent_id;
END;
