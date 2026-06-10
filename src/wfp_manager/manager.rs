use anyhow::{anyhow, Result};
use std::collections::HashMap;
use wfp::{
    ActionType, AppIdConditionBuilder, FilterBuilder, FilterEngineBuilder,
    InterfaceConditionBuilder, Layer, Transaction,
};

/// Tracks which profiles have active WFP filters
pub struct WfpManager {
    engine: wfp::FilterEngine,
    /// Maps profile_id → list of bound exe paths
    bindings: HashMap<String, Vec<String>>,
}

impl WfpManager {
    pub fn new() -> Result<Self> {
        let engine = FilterEngineBuilder::default()
            .dynamic()
            .open()
            .map_err(|e| anyhow!("Failed to open WFP engine: {e}"))?;

        Ok(Self {
            engine,
            bindings: HashMap::new(),
        })
    }

    /// Installs WFP filters for all apps in a profile.
    /// Called when a profile connects.
    pub fn install_profile_filters(
        &mut self,
        profile_id: &str,
        apps: &[String],
        _tunnel_luid: u64,
        _real_luid: u64,
    ) -> Result<()> {
        // Temporarily disabled — testing WinDivert routing without WFP block
        tracing::info!("WFP: skipping filter installation for testing");
        self.bindings.insert(profile_id.to_string(), apps.to_vec());
        Ok(())
    }

    /// Adds a single exe to an already-active profile's filters.
    /// Called when the user binds a new app to a connected profile.
    pub fn bind_exe(
        &mut self,
        profile_id: &str,
        exe_path: &str,
        tunnel_luid: u64,
        real_luid: u64,
    ) -> Result<()> {
        let transaction = Transaction::new(&mut self.engine)
            .map_err(|e| anyhow!("Failed to begin transaction: {e}"))?;

        add_exe_filters(&transaction, exe_path, tunnel_luid, real_luid)?;

        transaction.commit()
            .map_err(|e| anyhow!("Failed to commit transaction: {e}"))?;

        self.bindings
            .entry(profile_id.to_string())
            .or_default()
            .push(exe_path.to_string());

        tracing::info!("WFP: bound {} to profile {}", exe_path, profile_id);
        Ok(())
    }

    /// Removes all WFP filters for a profile.
    /// Called when a profile disconnects.
    /// Because we use a dynamic WFP session, filters are also automatically
    /// removed when the daemon exits — this handles the explicit disconnect case.
    pub fn remove_profile_filters(&mut self, profile_id: &str) -> Result<()> {
        if !self.bindings.contains_key(profile_id) {
            return Ok(());
        }

        // With a dynamic session, WFP doesn't expose a direct "remove sublayer"
        // API — filters tied to the session are cleaned up on engine close.
        // For per-profile removal while the daemon is running we need to
        // re-open a non-dynamic engine handle and delete by GUID.
        // For v0.1 we track this as disconnected and rely on session cleanup.
        // TODO: implement explicit filter removal for runtime disconnect.
        self.bindings.remove(profile_id);

        tracing::info!("WFP: removed filters for profile {}", profile_id);
        Ok(())
    }

    /// Returns the list of bound exe paths for a profile.
    pub fn get_bindings(&self, profile_id: &str) -> &[String] {
        self.bindings
            .get(profile_id)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Returns true if a profile has active WFP filters.
    pub fn is_installed(&self, profile_id: &str) -> bool {
        self.bindings.contains_key(profile_id)
    }
}

// ── Private helpers ───────────────────────────────────────────────────────────

fn add_exe_filters(
    transaction: &Transaction,
    exe_path: &str,
    tunnel_luid: u64,
    real_luid: u64,
) -> Result<()> {
    // Block this exe on the real network adapter
    let block_iface = InterfaceConditionBuilder::local()
        .luid(real_luid)
        .build();

    let block_app = AppIdConditionBuilder::new()
        .equal(exe_path)
        .map_err(|e| anyhow!("Failed to build app ID condition for {exe_path}: {e}"))?
        .build();

    FilterBuilder::default()
        .name(&format!("Tunnelbox-Block-{}", exe_name(exe_path)))
        .action(ActionType::Block)
        .layer(Layer::ConnectV4)
        .condition(block_iface)
        .condition(block_app)
        .weight(wfp::WeightRange::try_from(9).unwrap())
        .add(transaction)
        .map_err(|e| anyhow!("Failed to add block filter for {exe_path}: {e}"))?;

    // Permit this exe on the Wintun tunnel adapter
    let permit_iface = InterfaceConditionBuilder::local()
        .luid(tunnel_luid)
        .build();

    let permit_app = AppIdConditionBuilder::new()
        .equal(exe_path)
        .map_err(|e| anyhow!("Failed to build app ID condition for {exe_path}: {e}"))?
        .build();

    FilterBuilder::default()
        .name(&format!("Tunnelbox-Permit-{}", exe_name(exe_path)))
        .action(ActionType::Permit)
        .layer(Layer::ConnectV4)
        .condition(permit_iface)
        .condition(permit_app)
        .weight(wfp::WeightRange::try_from(10).unwrap())
        .add(transaction)
        .map_err(|e| anyhow!("Failed to add permit filter for {exe_path}: {e}"))?;

    tracing::debug!("WFP: added block+permit filters for {}", exe_path);
    Ok(())
}


/// Extracts just the filename from a full exe path for use in filter names.
fn exe_name(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}