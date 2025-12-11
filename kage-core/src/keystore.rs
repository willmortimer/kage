use crate::error::Result;

pub trait DeviceKeystore {
    fn ensure_key(&self, label: &str, policy: &str) -> Result<()>;
    fn wrap(&self, plaintext: &[u8], label: &str, policy: &str) -> Result<Vec<u8>>;
    fn unwrap(&self, ciphertext: &[u8], label: &str, policy: &str) -> Result<Vec<u8>>;
    fn delete_key(&self, label: &str) -> Result<()>; // Added for rotation
    fn is_available(&self) -> bool;
}
