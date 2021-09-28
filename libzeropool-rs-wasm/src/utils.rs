use web_sys::Performance;

pub fn set_panic_hook() {
    // When the `console_error_panic_hook` feature is enabled, we can call the
    // `set_panic_hook` function at least once during initialization, and then
    // we will get better error messages if our code ever panics.
    //
    // For more details see
    // https://github.com/rustwasm/console_error_panic_hook#readme
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

#[allow(dead_code)]
pub struct Timer {
    start: f64,
    perf: Performance,
}

impl Timer {
    #[allow(dead_code)]
    pub fn now() -> Timer {
        let perf = web_sys::window().unwrap().performance().unwrap();
        Timer {
            start: perf.now(),
            perf,
        }
    }

    #[allow(dead_code)]
    pub fn elapsed_s(&self) -> f64 {
        (self.perf.now() - self.start) / 1000.0
    }
}

macro_rules! js_err {
    ($msg:expr) => {
        JsValue::from(js_sys::Error::new($msg))
    };
    ($msg:tt, $($arg:expr),*) => {
        JsValue::from(js_sys::Error::new(&format!($msg, $($arg),*)))
    };
}
