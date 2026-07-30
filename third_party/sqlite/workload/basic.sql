.bail on
PRAGMA foreign_keys=ON;
PRAGMA journal_mode=DELETE;
PRAGMA synchronous=FULL;
CREATE TABLE accounts(
  account_id INTEGER PRIMARY KEY,
  balance INTEGER NOT NULL CHECK(balance >= 0)
);
CREATE TABLE transactions(
  txid TEXT NOT NULL PRIMARY KEY,
  from_account INTEGER NOT NULL REFERENCES accounts(account_id),
  to_account INTEGER NOT NULL REFERENCES accounts(account_id),
  amount INTEGER NOT NULL CHECK(amount > 0)
);
BEGIN IMMEDIATE;
INSERT INTO accounts(account_id, balance) VALUES(1, 1000), (2, 1000);
COMMIT;
BEGIN IMMEDIATE;
UPDATE accounts SET balance = balance - 125 WHERE account_id = 1;
UPDATE accounts SET balance = balance + 125 WHERE account_id = 2;
INSERT INTO transactions(txid, from_account, to_account, amount)
VALUES('tx-0001', 1, 2, 125);
COMMIT;
SELECT 'journal_mode=' || journal_mode FROM pragma_journal_mode;
SELECT 'synchronous=' || synchronous FROM pragma_synchronous;
SELECT 'account=' || account_id || ':' || balance FROM accounts ORDER BY account_id;
SELECT 'transaction=' || txid || ':' || from_account || ':' || to_account || ':' || amount
FROM transactions ORDER BY txid;
SELECT 'integrity=' || integrity_check FROM pragma_integrity_check;
SELECT 'foreign_keys=' || count(*) FROM pragma_foreign_key_check;
