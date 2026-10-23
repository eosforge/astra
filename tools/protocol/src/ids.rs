//! MessageID parsing and allocation shared by explicit generation and compatibility tests.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs, io,
    path::Path,
};

/// Preserves existing/deleted IDs and appends nonzero uint16 IDs for new messages in name order.
pub(crate) fn assign(previous: &str, messages: impl IntoIterator<Item = String>) -> io::Result<BTreeMap<u16, String>> {
    let mut ids = BTreeMap::new();
    let mut names = BTreeSet::new();
    // Reject corruption/merge conflicts instead of renumbering existing messages.
    for line in previous.lines().filter(|line| !line.trim().is_empty() && !line.starts_with('#')) {
        let mut fields = line.split_whitespace();
        let id = fields
            .next()
            .and_then(|id| id.parse::<u16>().ok())
            .ok_or_else(|| invalid("invalid message ID"))?;
        let name = fields.next().ok_or_else(|| invalid("missing message name"))?;
        if id == 0 || fields.next().is_some() || ids.insert(id, name.to_owned()).is_some() || !names.insert(name.to_owned()) {
            return Err(invalid("duplicate or invalid entry in proto/message-ids.lock"));
        }
    }
    // Sorting and deduplication make assignment independent of input order and platform.
    let messages: BTreeSet<_> = messages.into_iter().collect();
    for name in messages.difference(&names) {
        let id = ids
            .last_key_value()
            .map_or(0_u16, |(id, _)| *id)
            .checked_add(1)
            .ok_or_else(|| invalid("uint16 MessageID space exhausted"))?;
        ids.insert(id, name.clone());
    }
    Ok(ids)
}

/// Updates only when explicitly allowed; returns whether the registry changed.
pub(crate) fn store(path: &Path, previous: &str, current: &str, allow_update: bool) -> io::Result<bool> {
    if previous == current {
        return Ok(false);
    }
    if !allow_update {
        return Err(invalid("generated protocol is stale; run scripts/generate-proto; see proto/README.md"));
    }
    fs::write(path, current)?;
    Ok(true)
}

/// Reports invalid registry input without including untrusted field contents.
fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
