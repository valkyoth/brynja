//! Counter window for an unprivileged native AWS fixture.
#![forbid(unsafe_code)]
#[path = "../counter_window.rs"]
mod counter_window;

fn main() {
    counter_window::run();
}
