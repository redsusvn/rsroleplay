-- Removes exactly what seed.sql added. Rows are matched by their demo- id prefix.
DELETE FROM chat_history WHERE id LIKE 'demo-%';
DELETE FROM sketchboard WHERE id LIKE 'demo-%';
DELETE FROM memory_state WHERE id LIKE 'demo-%';
DELETE FROM chat_sessions WHERE id LIKE 'demo-%';
DELETE FROM personas WHERE id LIKE 'demo-%';
UPDATE user_prefs SET data = json_remove(data, '$.ui.scopes."persona:demo-a-havy"', '$.ui.scopes."persona:demo-b-kaede"', '$.ui.scopes."persona:demo-c-thalassa"', '$.ui.scopes."persona:demo-d-adrian"', '$.ui.scopes."persona:demo-e-rin"', '$.ui.scopes."persona:demo-f-khai"', '$.ui.scopes."persona:demo-g-lumi"', '$.ui.scopes."persona:demo-h-narrator"'), updated_at = CAST((julianday('now') - 2440587.5) * 86400000 AS INTEGER) WHERE json_extract(data, '$.ui.scopes') IS NOT NULL;
