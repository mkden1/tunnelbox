use anyhow::{anyhow, Result};
use std::collections::HashMap;
use wfp::{
    ActionType, AppIdConditionBuilder, FilterBuilder, FilterEngineBuilder,
    InterfaceConditionBuilder, Layer, Transaction, delete_filter_by_guid,
};
use wfp::GUID;

// ── Per-exe filter GUIDs stored so we can delete them at disconnect ───────────

struct FilterEntry {
    exe: String,
    block_guid: GUID,
    permit_guid: GUID,
}

/// Tracks which profiles have active WFP filters.
pub struct WfpManager {
    engine: wfp::FilterEngine,
    /// Maps profile_id → installed filter entries (one per app)
    filters: HashMap<String, Vec<FilterEntry>>,
}

impl WfpManager {
    pub fn new() -> Result<Self> {
        let engine = FilterEngineBuilder::default()
            .dynamic()
            .open()
            .map_err(|e| anyhow!("Failed to open WFP engine: {e}"))?;

        Ok(Self {
            engine,
            filters: HashMap::new(),
        })
    }

    /// Installs WFP block+permit filters for all apps in a profile.
    /// Called when a profile connects.
    ///
    /// Each app gets two filters on the ALE connect layer:
    ///   - Block on real adapter  (weight 9)  — prevents clearnet leaks
    ///   - Permit on Wintun       (weight 10) — allows tunnel traffic
    pub fn install_profile_filters(
        &mut self,
        profile_id: &str,
        apps: &[String],
        tunnel_luid: u64,
        real_luid: u64,
    ) -> Result<()> {
        if self.filters.contains_key(profile_id) {
            tracing::warn!("WFP: filters already installed for profile {}", profile_id);
            return Ok(());
        }

        let transaction = Transaction::new(&mut self.engine)
            .map_err(|e| anyhow!("Failed to begin WFP transaction: {e}"))?;

        let mut entries: Vec<FilterEntry> = Vec::with_capacity(apps.len());

        for exe in apps {
            let entry = add_exe_filters(&transaction, exe, tunnel_luid, real_luid)
                .map_err(|e| anyhow!("Failed to add WFP filters for {exe}: {e}"))?;
            entries.push(entry);
        }

        transaction
            .commit()
            .map_err(|e| anyhow!("Failed to commit WFP transaction: {e}"))?;

        self.filters.insert(profile_id.to_string(), entries);
        tracing::info!(
            "WFP: installed filters for {} apps in profile {}",
            apps.len(),
            profile_id
        );
        Ok(())
    }

    /// Adds a single exe to an already-active profile's filters at runtime.
    /// Called when the user binds a new app to a connected profile.
    pub fn bind_exe(
        &mut self,
        profile_id: &str,
        exe_path: &str,
        tunnel_luid: u64,
        real_luid: u64,
    ) -> Result<()> {
        let transaction = Transaction::new(&mut self.engine)
            .map_err(|e| anyhow!("Failed to begin WFP transaction: {e}"))?;

        let entry = add_exe_filters(&transaction, exe_path, tunnel_luid, real_luid)?;

        transaction
            .commit()
            .map_err(|e| anyhow!("Failed to commit WFP transaction: {e}"))?;

        self.filters
            .entry(profile_id.to_string())
            .or_default()
            .push(entry);

        tracing::info!("WFP: bound {} to profile {}", exe_path, profile_id);
        Ok(())
    }

    /// Removes all WFP filters for a profile.
    /// Called when a profile disconnects while the daemon is still running.
    ///
    /// Because we use a dynamic session, any filters not explicitly removed
    /// here will be cleaned up automatically when the daemon exits / the
    /// engine is dropped — so this is belt-and-braces for the runtime case.
    pub fn remove_profile_filters(&mut self, profile_id: &str) -> Result<()> {
        let entries = match self.filters.remove(profile_id) {
            Some(e) => e,
            None => return Ok(()),
        };

        let transaction = Transaction::new(&mut self.engine)
            .map_err(|e| anyhow!("Failed to begin WFP transaction for removal: {e}"))?;

        let mut errors: Vec<String> = Vec::new();

        for entry in &entries {
            if let Err(e) = delete_filter_by_guid(&transaction, &entry.block_guid) {
                errors.push(format!("{} block: {e}", entry.exe));
            }
            if let Err(e) = delete_filter_by_guid(&transaction, &entry.permit_guid) {
                errors.push(format!("{} permit: {e}", entry.exe));
            }
        }

        transaction
            .commit()
            .map_err(|e| anyhow!("Failed to commit WFP removal transaction: {e}"))?;

        if !errors.is_empty() {
            tracing::warn!(
                "WFP: some filters could not be removed for profile {}: {}",
                profile_id,
                errors.join(", ")
            );
        } else {
            tracing::info!(
                "WFP: removed {} filter pairs for profile {}",
                entries.len(),
                profile_id
            );
        }

        Ok(())
    }

    /// Returns the exe paths of all apps with active filters for a profile.
    pub fn get_bindings(&self, profile_id: &str) -> Vec<&str> {
        self.filters
            .get(profile_id)
            .map(|v| v.iter().map(|e| e.exe.as_str()).collect())
            .unwrap_or_default()
    }

    /// Returns true if a profile has active WFP filters.
    pub fn is_installed(&self, profile_id: &str) -> bool {
        self.filters.contains_key(profile_id)
    }
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// Adds block (on real adapter) + permit (on Wintun) filters for one exe.
/// Returns the GUIDs assigned to each filter so they can be removed later.
/// Must be called inside an open transaction.
fn add_exe_filters(
    transaction: &Transaction,
    exe_path: &str,
    tunnel_luid: u64,
    real_luid: u64,
) -> Result<FilterEntry> {
    let block_guid = new_guid();
    let permit_guid = new_guid();
    let name = exe_name(exe_path);

    // Block this exe on the real network adapter
    let block_iface = InterfaceConditionBuilder::local()
        .luid(real_luid)
        .build();

    let block_app = AppIdConditionBuilder::default()
        .equal(exe_path)
        .map_err(|e| anyhow!("Failed to build AppId condition for {exe_path}: {e}"))?
        .build();

    FilterBuilder::default()
        .name(format!("Tunnelbox-Block-{name}"))
        .action(ActionType::Block)
        .layer(Layer::ConnectV4)
        .guid(block_guid)
        .condition(block_iface)
        .condition(block_app)
        .weight(wfp::WeightRange::try_from(9).unwrap())
        .add(transaction)
        .map_err(|e| anyhow!("Failed to add block filter for {exe_path}: {e}"))?;

    // Permit this exe on the Wintun tunnel adapter
    let permit_iface = InterfaceConditionBuilder::local()
        .luid(tunnel_luid)
        .build();

    let permit_app = AppIdConditionBuilder::default()
        .equal(exe_path)
        .map_err(|e| anyhow!("Failed to build AppId condition for {exe_path}: {e}"))?
        .build();

    FilterBuilder::default()
        .name(format!("Tunnelbox-Permit-{name}"))
        .action(ActionType::Permit)
        .layer(Layer::ConnectV4)
        .guid(permit_guid)
        .condition(permit_iface)
        .condition(permit_app)
        .weight(wfp::WeightRange::try_from(10).unwrap())
        .add(transaction)
        .map_err(|e| anyhow!("Failed to add permit filter for {exe_path}: {e}"))?;

    tracing::debug!("WFP: queued block+permit filters for {}", exe_path);

    Ok(FilterEntry {
        exe: exe_path.to_string(),
        block_guid,
        permit_guid,
    })
}

/// Generates a random GUID using the Windows RNG via the `uuid` crate's random bytes.
/// We use `uuid::Uuid::new_v4` for the entropy and reinterpret the bytes as a GUID.
fn new_guid() -> GUID {
    let bytes = uuid::Uuid::new_v4().into_bytes();
    GUID {
        data1: u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
        data2: u16::from_le_bytes(bytes[4..6].try_into().unwrap()),
        data3: u16::from_le_bytes(bytes[6..8].try_into().unwrap()),
        data4: bytes[8..16].try_into().unwrap(),
    }
}

/// Extracts just the filename from a full exe path for use in filter display names.
fn exe_name(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}