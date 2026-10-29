use crate::ip::mmdb::mmdb_record::MMDBResult;
use log::warn;
use maxminddb::Reader;

pub struct MMDBReader {
    reader: Reader<Vec<u8>>,
}

impl MMDBReader {
    pub fn from(path: &str) -> Option<Self> {
        if let Ok(custom_reader) = maxminddb::Reader::open_readfile(path) {
            Some(MMDBReader {
                reader: custom_reader,
            })
        } else {
            None
        }
    }

    pub fn lookup(&mut self, address: &str) -> Option<MMDBResult> {
        //the address ultimately comes from a request header (when trust_proxy is on): an
        //unparsable IP must be a miss, not an unwrap panic that aborts the whole process
        let Ok(ip) = address.parse() else {
            warn!("Invalid ip for geo lookup: {address:?}");
            return None;
        };
        match self.reader.lookup(ip) {
            Err(e) => {
                warn!("Geo IP database error: {}", e);
                None
            }
            Ok(o) => {
                if let Ok(Some(result)) = o.decode() {
                    Some(result)
                } else {
                    warn!("Failed to deserialise Geo IP data {:?}", o);
                    None
                }
            }
        }
    }
}
