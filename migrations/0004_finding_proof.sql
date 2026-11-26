-- Replayable proof of a finding, as JSON text:
--   nuclei (with -include-rr): {kind:"http", replayable, request, response}
--   ZAP:                       {kind:"zap", replayable, method, attack, evidence}
-- Null when the tool reported no verifiable evidence. TEXT so new proof kinds
-- ship without another migration.
ALTER TABLE findings ADD COLUMN proof TEXT;
