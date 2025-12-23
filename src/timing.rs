#[cfg(not(target_arch = "wasm32"))]
pub struct Instant {
    inner: std::time::Instant,
}

#[cfg(target_arch = "wasm32")]
pub struct Instant {
    time_ms: f64,
}

impl Instant {
    #[cfg(not(target_arch = "wasm32"))]
    pub fn now() -> Self {
        Self {
            inner: std::time::Instant::now(),
        }
    }
    
    #[cfg(target_arch = "wasm32")]
    pub fn now() -> Self {
        Self {
            time_ms: web_sys::window()
                .expect("should have a Window")
                .performance()
                .expect("should have a Performance")
                .now(),
        }
    }
    
    #[cfg(not(target_arch = "wasm32"))]
    pub fn elapsed(&self) -> std::time::Duration {
        self.inner.elapsed()
    }
    
    #[cfg(target_arch = "wasm32")]
    pub fn elapsed(&self) -> std::time::Duration {
        let now = web_sys::window()
            .expect("should have a Window")
            .performance()
            .expect("should have a Performance")
            .now();
        
        let elapsed_ms = now - self.time_ms;
        std::time::Duration::from_millis(elapsed_ms as u64)
    }
}