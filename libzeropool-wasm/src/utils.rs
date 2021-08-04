use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
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

#[derive(Debug)]
pub struct Base64(pub Vec<u8>);

impl Serialize for Base64 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(&base64::display::Base64Display::with_config(
            &self.0,
            base64::STANDARD,
        ))
    }
}

impl<'de> Deserialize<'de> for Base64 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Vis;
        impl serde::de::Visitor<'_> for Vis {
            type Value = Base64;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a base64 string")
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                base64::decode(v).map(Base64).map_err(de::Error::custom)
            }
        }
        deserializer.deserialize_str(Vis)
    }
}

pub fn keccak256(data: &[u8]) -> [u8; 32] {
    use sha3::Digest;

    let mut hasher = sha3::Keccak256::new();
    hasher.update(data);
    let mut res = [0u8; 32];
    res.iter_mut()
        .zip(hasher.finalize().into_iter())
        .for_each(|(l, r)| *l = r);
    res
}

macro_rules! js_err {
    ($msg:expr) => {
        JsValue::from(js_sys::Error::new($msg))
    };
    ($msg:tt, $($arg:expr),*) => {
        JsValue::from(js_sys::Error::new(&format!($msg, $($arg),*)))
    };
}
