.bail on
PRAGMA foreign_keys=ON;
PRAGMA journal_mode=DELETE;
PRAGMA synchronous=FULL;
BEGIN IMMEDIATE;
UPDATE accounts SET balance = balance - 1 WHERE account_id <= 256;
UPDATE accounts SET balance = balance + 1 WHERE account_id > 256;
INSERT INTO transactions(txid, from_account, to_account, amount)
VALUES('tx-000001', 1, 512, 256);
COMMIT;
SELECT 'VISA_ACK|tx-000001';
