use std::{collections::BTreeSet, path::Path};

use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{ExpectedAcks, OracleFinding};

pub const SEMANTIC_PROJECTION_SCHEMA_VERSION: &str = "visa-sqlite-semantic-projection-v1";

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountRow {
    pub account_id: i64,
    pub balance: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransactionRow {
    pub txid: String,
    pub from_account: i64,
    pub to_account: i64,
    pub amount: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForeignKeyViolation {
    pub table: String,
    pub rowid: Option<i64>,
    pub parent: String,
    pub foreign_key_index: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchemaReport {
    pub accepted: bool,
    pub issues: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogicalRows {
    pub accounts: Vec<AccountRow>,
    pub transactions: Vec<TransactionRow>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BalanceReport {
    pub expected_total: i64,
    pub observed_total: i64,
    pub total_matches: bool,
    pub negative_accounts: u64,
    pub all_nonnegative: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransactionReport {
    pub rows: u64,
    pub nonnull_txids: u64,
    pub distinct_txids: u64,
    pub unique_txids: bool,
    pub nonpositive_amounts: u64,
    pub all_amounts_positive: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcknowledgementReport {
    pub expected_txids: Vec<String>,
    pub observed_txids: Vec<String>,
    pub missing_txids: Vec<String>,
    pub unexpected_txids: Vec<String>,
    pub exact_match: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SqliteReport {
    pub sqlite_version: String,
    pub integrity_check: Vec<String>,
    pub integrity_ok: bool,
    pub foreign_key_check: Vec<ForeignKeyViolation>,
    pub foreign_keys_ok: bool,
    pub schema: SchemaReport,
    pub logical_rows: LogicalRows,
    pub balance: BalanceReport,
    pub transactions: TransactionReport,
    pub acknowledgements: AcknowledgementReport,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogicalContentsProjection {
    pub account_rows: u64,
    pub accounts_sha256: String,
    pub transaction_rows: u64,
    pub transactions_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SqliteSemanticProjection {
    pub schema_version: String,
    pub logical_contents: LogicalContentsProjection,
    pub integrity_ok: bool,
    pub foreign_keys_ok: bool,
    pub schema_accepted: bool,
    pub balance: BalanceReport,
    pub transactions: TransactionReport,
    pub acknowledgements: AcknowledgementReport,
}

impl SqliteReport {
    pub fn semantic_projection(&self) -> SqliteSemanticProjection {
        SqliteSemanticProjection {
            schema_version: SEMANTIC_PROJECTION_SCHEMA_VERSION.to_owned(),
            logical_contents: LogicalContentsProjection {
                account_rows: self.logical_rows.accounts.len() as u64,
                accounts_sha256: account_rows_sha256(&self.logical_rows.accounts),
                transaction_rows: self.logical_rows.transactions.len() as u64,
                transactions_sha256: transaction_rows_sha256(&self.logical_rows.transactions),
            },
            integrity_ok: self.integrity_ok,
            foreign_keys_ok: self.foreign_keys_ok,
            schema_accepted: self.schema.accepted,
            balance: self.balance.clone(),
            transactions: self.transactions.clone(),
            acknowledgements: self.acknowledgements.clone(),
        }
    }

    pub(crate) fn findings(&self) -> Vec<OracleFinding> {
        let mut findings = Vec::new();
        if !self.integrity_ok {
            findings.push(OracleFinding::new(
                "sqlite-integrity-check",
                format!("PRAGMA integrity_check returned {:?}", self.integrity_check),
            ));
        }
        if !self.foreign_keys_ok {
            findings.push(OracleFinding::new(
                "sqlite-foreign-key-check",
                format!(
                    "PRAGMA foreign_key_check found {} violation(s)",
                    self.foreign_key_check.len()
                ),
            ));
        }
        if !self.schema.accepted {
            findings.push(OracleFinding::new("sqlite-stock-schema", self.schema.issues.join("; ")));
        }
        if !self.balance.total_matches {
            findings.push(OracleFinding::new(
                "sqlite-balance-sum",
                format!(
                    "expected total {}, observed {}",
                    self.balance.expected_total, self.balance.observed_total
                ),
            ));
        }
        if !self.balance.all_nonnegative {
            findings.push(OracleFinding::new(
                "sqlite-negative-balance",
                format!("{} account(s) have negative balances", self.balance.negative_accounts),
            ));
        }
        if !self.transactions.unique_txids {
            findings.push(OracleFinding::new(
                "sqlite-txid-unique",
                format!(
                    "{} rows, {} non-NULL txids, {} distinct txids",
                    self.transactions.rows,
                    self.transactions.nonnull_txids,
                    self.transactions.distinct_txids
                ),
            ));
        }
        if !self.transactions.all_amounts_positive {
            findings.push(OracleFinding::new(
                "sqlite-transaction-amount",
                format!(
                    "{} transaction(s) have nonpositive amounts",
                    self.transactions.nonpositive_amounts
                ),
            ));
        }
        if !self.acknowledgements.exact_match {
            findings.push(OracleFinding::new(
                "sqlite-acknowledged-txids",
                format!(
                    "missing {:?}; unexpected {:?}",
                    self.acknowledgements.missing_txids, self.acknowledgements.unexpected_txids
                ),
            ));
        }
        findings
    }
}

fn account_rows_sha256(rows: &[AccountRow]) -> String {
    let mut digest = Sha256::new();
    digest.update(b"visa-sqlite-account-rows-v1\0");
    digest.update((rows.len() as u64).to_be_bytes());
    for row in rows {
        digest.update(row.account_id.to_be_bytes());
        digest.update(row.balance.to_be_bytes());
    }
    hex::encode(digest.finalize())
}

fn transaction_rows_sha256(rows: &[TransactionRow]) -> String {
    let mut digest = Sha256::new();
    digest.update(b"visa-sqlite-transaction-rows-v1\0");
    digest.update((rows.len() as u64).to_be_bytes());
    for row in rows {
        let txid = row.txid.as_bytes();
        digest.update((txid.len() as u64).to_be_bytes());
        digest.update(txid);
        digest.update(row.from_account.to_be_bytes());
        digest.update(row.to_account.to_be_bytes());
        digest.update(row.amount.to_be_bytes());
    }
    hex::encode(digest.finalize())
}

pub(crate) fn inspect(
    database_path: &Path,
    expected: &ExpectedAcks,
) -> Result<SqliteReport, OracleFinding> {
    let connection = Connection::open_with_flags(
        database_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|error| sqlite_error("sqlite-open", error))?;
    connection
        .busy_timeout(std::time::Duration::ZERO)
        .map_err(|error| sqlite_error("sqlite-busy-timeout", error))?;
    connection
        .pragma_update(None, "foreign_keys", true)
        .map_err(|error| sqlite_error("sqlite-enable-foreign-keys", error))?;
    let sqlite_version = connection
        .query_row("SELECT sqlite_version()", [], |row| row.get(0))
        .map_err(|error| sqlite_error("sqlite-version", error))?;
    let integrity_check =
        string_column(&connection, "PRAGMA integrity_check", "sqlite-integrity-query")?;
    let integrity_ok = integrity_check.as_slice() == ["ok"];
    let foreign_key_check = foreign_key_check(&connection)?;
    let foreign_keys_ok = foreign_key_check.is_empty();
    let schema = inspect_schema(&connection)?;
    let mut accounts = query_accounts(&connection)?;
    let mut transactions = query_transactions(&connection)?;
    accounts.sort();
    transactions.sort();
    let (observed_total, negative_accounts): (i64, i64) = connection
        .query_row(
            "SELECT COALESCE(SUM(balance), 0),\
             COALESCE(SUM(CASE WHEN balance < 0 THEN 1 ELSE 0 END), 0) FROM accounts",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|error| sqlite_error("sqlite-balance-query", error))?;
    let (rows, nonnull_txids, distinct_txids, nonpositive_amounts): (i64, i64, i64, i64) =
        connection
            .query_row(
                "SELECT COUNT(*), COUNT(txid), COUNT(DISTINCT txid),\
                 COALESCE(SUM(CASE WHEN amount <= 0 THEN 1 ELSE 0 END), 0) FROM transactions",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .map_err(|error| sqlite_error("sqlite-transaction-invariants", error))?;
    let expected_txids = sorted(expected.acknowledged_txids.clone());
    let observed_txids = sorted(transactions.iter().map(|row| row.txid.clone()).collect());
    let expected_set = expected_txids.iter().cloned().collect::<BTreeSet<_>>();
    let observed_set = observed_txids.iter().cloned().collect::<BTreeSet<_>>();
    let missing_txids = expected_set.difference(&observed_set).cloned().collect();
    let unexpected_txids = observed_set.difference(&expected_set).cloned().collect();
    let exact_match = expected_txids == observed_txids;
    let rows = unsigned(rows, "transaction row count")?;
    let nonnull_txids = unsigned(nonnull_txids, "nonnull txid count")?;
    let distinct_txids = unsigned(distinct_txids, "distinct txid count")?;
    let nonpositive_amounts = unsigned(nonpositive_amounts, "nonpositive amount count")?;
    let negative_accounts = unsigned(negative_accounts, "negative account count")?;
    Ok(SqliteReport {
        sqlite_version,
        integrity_check,
        integrity_ok,
        foreign_key_check,
        foreign_keys_ok,
        schema,
        logical_rows: LogicalRows { accounts, transactions },
        balance: BalanceReport {
            expected_total: expected.initial_total_balance,
            observed_total,
            total_matches: observed_total == expected.initial_total_balance,
            negative_accounts,
            all_nonnegative: negative_accounts == 0,
        },
        transactions: TransactionReport {
            rows,
            nonnull_txids,
            distinct_txids,
            unique_txids: rows == nonnull_txids && rows == distinct_txids,
            nonpositive_amounts,
            all_amounts_positive: nonpositive_amounts == 0,
        },
        acknowledgements: AcknowledgementReport {
            expected_txids,
            observed_txids,
            missing_txids,
            unexpected_txids,
            exact_match,
        },
    })
}

fn inspect_schema(connection: &Connection) -> Result<SchemaReport, OracleFinding> {
    let accounts = table_columns(connection, "accounts")?;
    let transactions = table_columns(connection, "transactions")?;
    let mut issues = Vec::new();
    let expected_accounts = [
        Column {
            name: "account_id".to_owned(),
            declared_type: "INTEGER".to_owned(),
            not_null: false,
            primary_key: 1,
        },
        Column {
            name: "balance".to_owned(),
            declared_type: "INTEGER".to_owned(),
            not_null: true,
            primary_key: 0,
        },
    ];
    let expected_transactions = [
        Column {
            name: "txid".to_owned(),
            declared_type: "TEXT".to_owned(),
            not_null: true,
            primary_key: 1,
        },
        Column {
            name: "from_account".to_owned(),
            declared_type: "INTEGER".to_owned(),
            not_null: true,
            primary_key: 0,
        },
        Column {
            name: "to_account".to_owned(),
            declared_type: "INTEGER".to_owned(),
            not_null: true,
            primary_key: 0,
        },
        Column {
            name: "amount".to_owned(),
            declared_type: "INTEGER".to_owned(),
            not_null: true,
            primary_key: 0,
        },
    ];
    if accounts != expected_accounts {
        issues.push(format!("accounts columns differ: {accounts:?}"));
    }
    if transactions != expected_transactions {
        issues.push(format!("transactions columns differ: {transactions:?}"));
    }
    let foreign_keys = foreign_key_schema(connection)?;
    let expected_foreign_keys = BTreeSet::from([
        ("from_account".to_owned(), "accounts".to_owned(), "account_id".to_owned()),
        ("to_account".to_owned(), "accounts".to_owned(), "account_id".to_owned()),
    ]);
    if foreign_keys != expected_foreign_keys {
        issues.push(format!("transactions foreign keys differ: {foreign_keys:?}"));
    }
    Ok(SchemaReport { accepted: issues.is_empty(), issues })
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Column {
    name: String,
    declared_type: String,
    not_null: bool,
    primary_key: i64,
}

fn table_columns(connection: &Connection, table: &str) -> Result<Vec<Column>, OracleFinding> {
    let sql = format!("PRAGMA table_info({table})");
    let mut statement =
        connection.prepare(&sql).map_err(|error| sqlite_error("sqlite-schema-columns", error))?;
    statement
        .query_map([], |row| {
            Ok(Column {
                name: row.get(1)?,
                declared_type: row.get::<_, String>(2)?.to_ascii_uppercase(),
                not_null: row.get::<_, i64>(3)? != 0,
                primary_key: row.get(5)?,
            })
        })
        .map_err(|error| sqlite_error("sqlite-schema-columns", error))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| sqlite_error("sqlite-schema-columns", error))
}

fn foreign_key_schema(
    connection: &Connection,
) -> Result<BTreeSet<(String, String, String)>, OracleFinding> {
    let mut statement = connection
        .prepare("PRAGMA foreign_key_list(transactions)")
        .map_err(|error| sqlite_error("sqlite-schema-foreign-keys", error))?;
    statement
        .query_map([], |row| Ok((row.get(3)?, row.get(2)?, row.get(4)?)))
        .map_err(|error| sqlite_error("sqlite-schema-foreign-keys", error))?
        .collect::<Result<BTreeSet<_>, _>>()
        .map_err(|error| sqlite_error("sqlite-schema-foreign-keys", error))
}

fn foreign_key_check(connection: &Connection) -> Result<Vec<ForeignKeyViolation>, OracleFinding> {
    let mut statement = connection
        .prepare("PRAGMA foreign_key_check")
        .map_err(|error| sqlite_error("sqlite-foreign-key-query", error))?;
    let mut violations = statement
        .query_map([], |row| {
            Ok(ForeignKeyViolation {
                table: row.get(0)?,
                rowid: row.get(1)?,
                parent: row.get(2)?,
                foreign_key_index: row.get(3)?,
            })
        })
        .map_err(|error| sqlite_error("sqlite-foreign-key-query", error))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| sqlite_error("sqlite-foreign-key-query", error))?;
    violations.sort();
    Ok(violations)
}

fn query_accounts(connection: &Connection) -> Result<Vec<AccountRow>, OracleFinding> {
    let mut statement = connection
        .prepare("SELECT account_id, balance FROM accounts")
        .map_err(|error| sqlite_error("sqlite-accounts-query", error))?;
    statement
        .query_map([], |row| Ok(AccountRow { account_id: row.get(0)?, balance: row.get(1)? }))
        .map_err(|error| sqlite_error("sqlite-accounts-query", error))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| sqlite_error("sqlite-accounts-query", error))
}

fn query_transactions(connection: &Connection) -> Result<Vec<TransactionRow>, OracleFinding> {
    let mut statement = connection
        .prepare("SELECT txid, from_account, to_account, amount FROM transactions")
        .map_err(|error| sqlite_error("sqlite-transactions-query", error))?;
    statement
        .query_map([], |row| {
            Ok(TransactionRow {
                txid: row.get(0)?,
                from_account: row.get(1)?,
                to_account: row.get(2)?,
                amount: row.get(3)?,
            })
        })
        .map_err(|error| sqlite_error("sqlite-transactions-query", error))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| sqlite_error("sqlite-transactions-query", error))
}

fn string_column(
    connection: &Connection,
    sql: &str,
    code: &'static str,
) -> Result<Vec<String>, OracleFinding> {
    let mut statement = connection.prepare(sql).map_err(|error| sqlite_error(code, error))?;
    statement
        .query_map([], |row| row.get(0))
        .map_err(|error| sqlite_error(code, error))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| sqlite_error(code, error))
}

fn sorted(mut values: Vec<String>) -> Vec<String> {
    values.sort();
    values
}

fn unsigned(value: i64, label: &'static str) -> Result<u64, OracleFinding> {
    u64::try_from(value).map_err(|_| {
        OracleFinding::new(
            "sqlite-negative-count",
            format!("{label} unexpectedly returned {value}"),
        )
    })
}

fn sqlite_error(code: &'static str, error: rusqlite::Error) -> OracleFinding {
    OracleFinding::new(code, error.to_string())
}
