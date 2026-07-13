-- Idempotency + bounded growth for the append-only observations log.
--
-- The v1 schema was pure append-only: replaying the same batch (retry after
-- a transient failure, a cron misconfiguration, the prober cadence loop)
-- would insert duplicate rows unboundedly. The scoring engine only reads
-- the newest row per (agent_id, signal_id), so those duplicates were pure
-- storage overhead.
--
-- The unique index below turns a same-(agent, signal, observedAt) re-insert
-- into a no-op when AppendObservation uses ON CONFLICT DO NOTHING; the
-- retention pruner (see DB.PruneObservations) then bounds long-term growth
-- by trimming to the K most recent rows per pair.

CREATE UNIQUE INDEX IF NOT EXISTS uq_signal_observations_agent_signal_time
    ON signal_observations (agent_id, signal_id, observed_at);
