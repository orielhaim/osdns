#[cfg(feature = "tracing")]
macro_rules! osdns_warn {
    ($($arg:tt)*) => { tracing::warn!($($arg)*) };
}

#[cfg(not(feature = "tracing"))]
macro_rules! osdns_warn {
    ($($arg:tt)*) => {{}};
}
