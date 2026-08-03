//! Redaction newtypes. Anything sensitive lives inside [`Secret`] so it can
//! never be Debug/Display-logged or serialized by accident.

use zeroize::Zeroize;

/// Wrapper that redacts its contents in Debug/Display and zeroizes on drop.
/// Deliberately does NOT implement Serialize/Deserialize or Clone-into-log.
pub struct Secret<T: Zeroize>(T);

impl<T: Zeroize> Secret<T> {
    pub fn new(inner: T) -> Self {
        Self(inner)
    }

    /// Access the secret. Callers must not log or serialize the value.
    pub fn expose(&self) -> &T {
        &self.0
    }

    pub fn expose_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl<T: Zeroize> Drop for Secret<T> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<T: Zeroize> std::fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl<T: Zeroize> std::fmt::Display for Secret<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

pub type SecretBytes = Secret<Vec<u8>>;
pub type SecretString = Secret<String>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_and_display_redact() {
        let s = Secret::new(String::from("hunter2"));
        assert_eq!(format!("{s:?}"), "[REDACTED]");
        assert_eq!(format!("{s}"), "[REDACTED]");
        assert_eq!(s.expose(), "hunter2");
    }
}
