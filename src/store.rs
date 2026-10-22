use crate::model::Entry;
use anyhow::Result;
use rusqlite::{Connection, params};
use std::path::Path;

pub struct Store {
    db: Connection,
    limit: usize,
}
impl Store {
    pub fn open(path: &Path, limit: usize) -> Result<Self> {
        Self::init(Connection::open(path)?, limit)
    }
    pub fn memory(limit: usize) -> Result<Self> {
        Self::init(Connection::open_in_memory()?, limit)
    }
    fn init(db: Connection, limit: usize) -> Result<Self> {
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=3000;
            CREATE TABLE IF NOT EXISTS decisions (seq INTEGER PRIMARY KEY, id TEXT UNIQUE NOT NULL, entry TEXT NOT NULL);")?;
        Ok(Self { db, limit })
    }
    pub fn record(&mut self, entry: &Entry) -> Result<()> {
        let tx = self.db.transaction()?;
        tx.execute(
            "INSERT INTO decisions(id, entry) VALUES (?1, ?2)",
            params![entry.id, serde_json::to_string(entry)?],
        )?;
        tx.execute("DELETE FROM decisions WHERE seq NOT IN (SELECT seq FROM decisions ORDER BY seq DESC LIMIT ?1)", [self.limit])?;
        tx.commit()?;
        Ok(())
    }
    pub fn recent(&self, limit: usize) -> Result<Vec<Entry>> {
        let mut statement = self
            .db
            .prepare("SELECT entry FROM decisions ORDER BY seq DESC LIMIT ?1")?;
        let values = statement.query_map([limit], |row| row.get::<_, String>(0))?;
        values
            .map(|value| Ok(serde_json::from_str(&value?)?))
            .collect()
    }
}
