.bail on
PRAGMA page_size=512;
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
WITH RECURSIVE ids(account_id) AS (
  VALUES(1)
  UNION ALL
  SELECT account_id + 1 FROM ids WHERE account_id < 512
)
INSERT INTO accounts(account_id, balance)
SELECT account_id, 1000 FROM ids;
COMMIT;
SELECT 'VISA_SEED|accounts=' || count(*) || '|balance=' || sum(balance)
FROM accounts;
