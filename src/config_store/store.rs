use anyhow::{anyhow, Result};

use super::paths;
use super::profile::Profile;

pub struct ConfigStore;

impl ConfigStore {
    /// Initialises the data directory structure.
    pub fn init() -> Result<()> {
        paths::ensure_dirs()?;
        Ok(())
    }

    /// Loads all profiles from disk.
    pub fn load_all() -> Result<Vec<Profile>> {
        let profiles_dir = paths::profiles_dir()?;

        if !profiles_dir.exists() {
            return Ok(Vec::new());
        }

        let mut profiles = Vec::new();

        for entry in std::fs::read_dir(&profiles_dir)
            .map_err(|e| anyhow!("Failed to read profiles directory: {e}"))?
        {
            let entry = entry?;
            let path = entry.path();

            if !path.is_dir() {
                continue;
            }

            let id = path
                .file_name()
                .and_then(|n| n.to_str())
                .ok_or_else(|| anyhow!("Invalid profile directory name"))?
                .to_string();

            match Profile::load(&id) {
                Ok(profile) => profiles.push(profile),
                Err(e) => {
                    // Log and skip corrupted profiles rather than failing entirely
                    eprintln!("Warning: skipping corrupted profile {id}: {e}");
                }
            }
        }

        // Sort by name for consistent ordering
        profiles.sort_by(|a, b| a.name.cmp(&b.name));

        Ok(profiles)
    }

    /// Returns a single profile by ID.
    pub fn get(id: &str) -> Result<Profile> {
        Profile::load(id)
    }

    /// Creates a new profile and saves it to disk.
    pub fn create(name: &str) -> Result<Profile> {
        // Check for duplicate names
        let existing = Self::load_all()?;
        if existing.iter().any(|p| p.name.eq_ignore_ascii_case(name)) {
            return Err(anyhow!("A profile named '{}' already exists", name));
        }

        let profile = Profile::new(name);
        profile.save()?;
        Ok(profile)
    }

    /// Updates an existing profile on disk.
    pub fn update(profile: &Profile) -> Result<()> {
        // Verify it exists before updating
        let path = paths::profile_json_path(&profile.id)?;
        if !path.exists() {
            return Err(anyhow!("Profile {} does not exist", profile.id));
        }
        profile.save()
    }

    /// Deletes a profile and its wireguard.conf by ID.
    pub fn delete(id: &str) -> Result<()> {
        Profile::delete(id)
    }

    /// Imports a WireGuard .conf file into an existing profile.
    pub fn import_wireguard_conf(id: &str, contents: &str) -> Result<()> {
        let profile = Profile::load(id)?;
        profile.save_wireguard_conf(contents)
    }
}