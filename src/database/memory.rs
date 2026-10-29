use crate::database::Database;
use crate::results::TelemetryData;
use async_trait::async_trait;
use dashmap::DashMap;
use log::info;
use std::sync::Arc;
use tokio::sync::Mutex;

pub struct MemoryDB {
    pub records: DashMap<String, TelemetryData>,
}

impl MemoryDB {
    pub fn init() -> Arc<Mutex<MemoryDB>> {
        info!("Database in-memory initialized successfully");
        Arc::new(Mutex::new(MemoryDB {
            records: DashMap::new(),
        }))
    }
}

#[async_trait]
impl Database for MemoryDB {
    async fn insert(&mut self, data: TelemetryData) -> std::io::Result<()> {
        self.records.insert(data.uuid.clone(), data);
        if self.records.len() > 100 {
            //DashMap iteration order is arbitrary; evicting by iteration drops a random record and
            //lets the "last 100" silently lose the actual newest entries
            let oldest = self
                .records
                .iter()
                .min_by_key(|entry| entry.value().timestamp)
                .map(|entry| entry.key().clone());
            if let Some(key) = oldest {
                self.records.remove(&key);
            }
        }
        Ok(())
    }

    async fn fetch_by_uuid(&mut self, uuid: &str) -> std::io::Result<Option<TelemetryData>> {
        Ok(self.records.get(uuid).as_deref().cloned())
    }

    async fn fetch_last_100(&mut self) -> std::io::Result<Vec<TelemetryData>> {
        //match the SQL backends' contract: newest first, so the stats page reads sensibly
        let mut data: Vec<TelemetryData> = self
            .records
            .iter()
            .map(|item| item.value().clone())
            .collect();
        data.sort_by_key(|a| std::cmp::Reverse(a.timestamp));
        Ok(data)
    }
}
