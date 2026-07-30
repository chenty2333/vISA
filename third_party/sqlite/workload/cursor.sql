.bail on
PRAGMA foreign_keys=ON;
PRAGMA query_only=ON;
SELECT 'VISA_ROW|' || account_id || '|' || balance
FROM accounts
ORDER BY account_id;
SELECT 'VISA_CURSOR_DONE|512';
