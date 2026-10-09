//! Clock abstraction: time as an injectable dependency.
//!
//! Policies that depend on time ([`crate::TimeWindowPolicy`],
//! [`crate::RateLimitPolicy`]) take a [`Clock`] instead of calling the
//! system clock directly. Production uses [`SystemClock`]; tests use
//! [`ManualClock`], which makes time-dependent behavior deterministic.

/// Source of wall-clock time, in seconds since the Unix epoch.
///
/// Object-safe and `Send + Sync` so policies can hold it behind a trait object.
pub trait Clock: Send + Sync {
    /// Current time as seconds since 1970-01-01T00:00:00Z.
    fn now_unix_secs(&self) -> u64;
}

/// [`Clock`] backed by the real system clock.
///
/// Time moves on its own; suitable for production, useless for tests.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix_secs(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

/// [`Clock`] with manually controlled time, for deterministic tests.
///
/// Interior mutability lets tests advance time through a shared reference.
/// Starts at the Unix epoch unless set otherwise.
#[derive(Debug, Default)]
pub struct ManualClock {
    now: std::sync::Mutex<u64>,
}

impl ManualClock {
    /// Creates a clock fixed at `unix_secs`.
    pub fn new(unix_secs: u64) -> Self {
        Self {
            now: std::sync::Mutex::new(unix_secs),
        }
    }

    /// Moves the clock to `unix_secs`.
    pub fn set(&self, unix_secs: u64) {
        *self.now.lock().unwrap_or_else(|e| e.into_inner()) = unix_secs;
    }

    /// Moves the clock forward by `delta_secs`.
    pub fn advance(&self, delta_secs: u64) {
        *self.now.lock().unwrap_or_else(|e| e.into_inner()) += delta_secs;
    }
}

impl Clock for ManualClock {
    fn now_unix_secs(&self) -> u64 {
        *self.now.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Blanket impl so clocks can be shared by reference.
///
/// Policies take `C: Clock` by value; tests (and callers) often need to keep
/// driving the same clock after handing it to a policy. `&ManualClock` works
/// because the interior mutability lives inside the clock itself.
impl<T: Clock> Clock for &T {
    fn now_unix_secs(&self) -> u64 {
        (**self).now_unix_secs()
    }
}
