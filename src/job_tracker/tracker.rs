use anyhow::{anyhow, Result};
use std::collections::HashMap;

use super::job::JobObject;

pub struct JobTracker {
    /// One Job Object per connected profile
    jobs: HashMap<String, JobObject>,
}

impl JobTracker {
    pub fn new() -> Self {
        Self {
            jobs: HashMap::new(),
        }
    }

    /// Creates a Job Object for a profile.
    /// Called when a profile connects.
    pub fn create_job(&mut self, profile_id: &str) -> Result<()> {
        if self.jobs.contains_key(profile_id) {
            return Ok(());
        }
        let job = JobObject::new(profile_id)?;
        self.jobs.insert(profile_id.to_string(), job);
        tracing::info!("Job Object created for profile {}", profile_id);
        Ok(())
    }

    /// Launches an exe inside the profile's Job Object.
    /// The process is guaranteed to be inside the job before
    /// any network activity occurs.
    pub fn launch(
        &mut self,
        profile_id: &str,
        exe_path: &str,
        args: &[String],
    ) -> Result<u32> {
        let job = self.jobs.get_mut(profile_id)
            .ok_or_else(|| anyhow!("No Job Object for profile {}", profile_id))?;
        job.spawn(exe_path, args)
    }

    /// Returns all PIDs running under a profile's job.
    pub fn get_pids(&self, profile_id: &str) -> Vec<u32> {
        self.jobs
            .get(profile_id)
            .map(|j| j.pids())
            .unwrap_or_default()
    }

    /// Destroys the Job Object for a profile, killing all its processes.
    /// Called when a profile disconnects.
    pub fn remove_job(&mut self, profile_id: &str) {
        if self.jobs.remove(profile_id).is_some() {
            tracing::info!("Job Object removed for profile {}", profile_id);
        }
    }

    /// Returns true if a profile has an active Job Object.
    pub fn has_job(&self, profile_id: &str) -> bool {
        self.jobs.contains_key(profile_id)
    }
}