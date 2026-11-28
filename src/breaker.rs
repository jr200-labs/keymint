use anyhow::ensure;
use std::{
    sync::Mutex,
    time::{Duration, Instant},
};

pub struct Breaker(Mutex<Window>);

struct Window {
    started: Instant,
    opened: Option<Instant>,
    probing: bool,
    generation: u64,
    completed: u32,
    failures: u32,
}

impl Default for Breaker {
    fn default() -> Self {
        Self(Mutex::new(Window {
            started: Instant::now(),
            opened: None,
            probing: false,
            generation: 0,
            completed: 0,
            failures: 0,
        }))
    }
}

impl Breaker {
    pub fn state(&self) -> i64 {
        let state = self.0.lock().expect("circuit breaker lock");
        match state.opened {
            None => 0,
            Some(opened) if opened.elapsed() >= Duration::from_secs(30) => 1,
            Some(_) => 2,
        }
    }

    pub fn begin(&self) -> anyhow::Result<Attempt<'_>> {
        let mut state = self.0.lock().expect("circuit breaker lock");
        let now = Instant::now();
        if let Some(opened) = state.opened {
            ensure!(
                now.duration_since(opened) >= Duration::from_secs(30) && !state.probing,
                "upstream circuit breaker open"
            );
            state.probing = true;
        } else if now.duration_since(state.started) >= Duration::from_secs(60) {
            state.reset(now);
        }
        Ok(Attempt {
            breaker: self,
            generation: state.generation,
            probe: state.probing,
            classified: None,
        })
    }
}

impl Window {
    fn reset(&mut self, now: Instant) {
        self.started = now;
        self.completed = 0;
        self.failures = 0;
        self.probing = false;
        self.opened = None;
        self.generation = self.generation.wrapping_add(1);
    }
}

pub struct Attempt<'a> {
    breaker: &'a Breaker,
    generation: u64,
    probe: bool,
    classified: Option<bool>,
}

impl Attempt<'_> {
    pub fn finish(mut self, succeeded: bool) {
        self.classified = Some(succeeded);
    }
}

impl Drop for Attempt<'_> {
    fn drop(&mut self) {
        let mut state = self.breaker.0.lock().expect("circuit breaker lock");
        if state.generation != self.generation {
            return;
        }
        let now = Instant::now();
        let succeeded = self.classified.unwrap_or(false);
        if self.probe && succeeded {
            state.reset(now);
            return;
        }
        state.completed = state.completed.saturating_add(1);
        state.failures = state.failures.saturating_add(u32::from(!succeeded));
        if self.probe || (state.completed >= 10 && state.failures > state.completed / 2) {
            state.reset(now);
            state.opened = Some(now);
        }
    }
}
