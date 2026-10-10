//! Sealing run data with the tenant's data key.
//!
//! Run inputs and outputs, step results, human answers and questions are stored in the journal
//! sealed under the tenant DEK (AES-256-GCM, the same envelope code as BYOK keys and datasource
//! credentials), with the tenant id and the run id as associated data: a sealed value cannot be
//! moved to another tenant or another run. Deleting a tenant destroys its DEK, which makes its
//! journal unreadable (crypto-shredding).

use caliban_config::Dek;
use std::sync::Arc;

/// Seals and opens journal values for a tenant.
pub trait Sealer: Send + Sync {
    fn seal(&self, tenant: &str, run_id: &str, plaintext: &str) -> Result<String, String>;
    fn open(&self, tenant: &str, run_id: &str, sealed: &str) -> Result<String, String>;
}

/// The associated-data label for journal values: tenant and run.
fn context(tenant: &str, run_id: &str) -> String {
    format!("journal\0{tenant}\0{run_id}")
}

/// Seals with a DEK found per tenant (the data plane finds it in the snapshot and unwraps it with
/// its keyring).
pub struct DekSealer<F> {
    find: F,
}

impl<F> DekSealer<F>
where
    F: Fn(&str) -> Result<Arc<Dek>, String> + Send + Sync,
{
    pub fn new(find: F) -> Self {
        Self { find }
    }
}

impl<F> Sealer for DekSealer<F>
where
    F: Fn(&str) -> Result<Arc<Dek>, String> + Send + Sync,
{
    fn seal(&self, tenant: &str, run_id: &str, plaintext: &str) -> Result<String, String> {
        Ok((self.find)(tenant)?.seal_with(tenant, &context(tenant, run_id), plaintext))
    }

    fn open(&self, tenant: &str, run_id: &str, sealed: &str) -> Result<String, String> {
        (self.find)(tenant)?.open_with(tenant, &context(tenant, run_id), sealed)
    }
}

/// One random DEK per tenant, in memory (tests and examples).
#[derive(Default)]
pub struct TestSealer {
    keys: parking_lot::Mutex<std::collections::HashMap<String, Arc<Dek>>>,
}

impl TestSealer {
    pub fn dek(&self, tenant: &str) -> Arc<Dek> {
        Arc::clone(self.keys.lock().entry(tenant.to_owned()).or_insert_with(|| Arc::new(Dek::generate())))
    }
}

impl Sealer for TestSealer {
    fn seal(&self, tenant: &str, run_id: &str, plaintext: &str) -> Result<String, String> {
        Ok(self.dek(tenant).seal_with(tenant, &context(tenant, run_id), plaintext))
    }

    fn open(&self, tenant: &str, run_id: &str, sealed: &str) -> Result<String, String> {
        self.dek(tenant).open_with(tenant, &context(tenant, run_id), sealed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_are_bound_to_tenant_and_run() {
        let s = TestSealer::default();
        let sealed = s.seal("acme", "run_1", "secret answer").unwrap();
        assert!(!sealed.contains("secret"));
        assert_eq!(s.open("acme", "run_1", &sealed).unwrap(), "secret answer");
        assert!(s.open("acme", "run_2", &sealed).is_err(), "moved to another run");
        assert!(s.open("globex", "run_1", &sealed).is_err(), "moved to another tenant");
    }
}
