use argon2::{
    Algorithm, Argon2, Params, Version,
    password_hash::{self, PasswordHasher, SaltString},
};
use base64::{Engine as _, engine::general_purpose};
use chrono::offset;

/// Bounds for the Argon2 parameters accepted from the UI.
pub const ARGON2_M_MIN: u32 = 8 * 1024; // 8 MiB
pub const ARGON2_M_MAX: u32 = 1024 * 1024; // 1 GiB
pub const ARGON2_T_MIN: u32 = 1;
pub const ARGON2_T_MAX: u32 = 100;
pub const ARGON2_P_MIN: u32 = 1;
pub const ARGON2_P_MAX: u32 = 256;

/// Bounds (in bytes) for generated random keys.
pub const KEY_LEN_MIN: u32 = 8;
pub const KEY_LEN_MAX: u32 = 256;

const SALT_LEN: usize = 16;

// Compile-time sanity checks for the UI bounds.
const _: () = {
    assert!(ARGON2_M_MIN <= ARGON2_M_MAX);
    assert!(ARGON2_T_MIN <= ARGON2_T_MAX);
    assert!(ARGON2_P_MIN <= ARGON2_P_MAX);
    assert!(KEY_LEN_MIN <= KEY_LEN_MAX);
    // Argon2 requires m >= 8 * p for every combination the UI allows.
    assert!(ARGON2_M_MIN >= 8 * ARGON2_P_MAX);
};

fn hash_password_argon2(
    alg: Algorithm,
    password: &str,
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<String, password_hash::Error> {
    let salt_bytes: [u8; SALT_LEN] = rand::random();
    let salt = SaltString::encode_b64(&salt_bytes)?;
    let params = Params::new(m_cost, t_cost, p_cost, None)?;
    let argon2 = Argon2::new(alg, Version::V0x13, params);
    Ok(argon2
        .hash_password(password.as_bytes(), &salt)?
        .to_string())
}

/// Hashes `password` with Argon2id and a fresh random salt, returning a PHC string.
pub fn hash_password_argon2id(
    password: &str,
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<String, password_hash::Error> {
    hash_password_argon2(Algorithm::Argon2id, password, m_cost, t_cost, p_cost)
}

/// Hashes `password` with Argon2i and a fresh random salt, returning a PHC string.
pub fn hash_password_argon2i(
    password: &str,
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<String, password_hash::Error> {
    hash_password_argon2(Algorithm::Argon2i, password, m_cost, t_cost, p_cost)
}

/// Argon2 flavour selectable from the UI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Argon2Variant {
    Id,
    I,
}

impl Argon2Variant {
    pub fn name(self) -> &'static str {
        match self {
            Argon2Variant::Id => "Argon2id",
            Argon2Variant::I => "Argon2i",
        }
    }
}

/// Hashes `password` with the selected Argon2 variant, mapping errors to a
/// human-readable message.
pub fn hash_password(
    variant: Argon2Variant,
    password: &str,
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<String, String> {
    let alg = match variant {
        Argon2Variant::Id => Algorithm::Argon2id,
        Argon2Variant::I => Algorithm::Argon2i,
    };
    hash_password_argon2(alg, password, m_cost, t_cost, p_cost)
        .map_err(|e| format!("{} error: {e}", variant.name()))
}

/// Runs [`hash_password`] on a background thread so the caller (the UI thread)
/// stays responsive. `on_done` is invoked from the worker thread once the result
/// is ready, after which joining the returned handle does not block.
///
/// A panic inside the worker is converted to an `Err` and `on_done` is still
/// called, so the UI never waits forever.
pub fn spawn_hash<F>(
    variant: Argon2Variant,
    password: String,
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
    on_done: F,
) -> std::io::Result<std::thread::JoinHandle<Result<String, String>>>
where
    F: FnOnce() + Send + 'static,
{
    std::thread::Builder::new()
        .name("argon2-worker".into())
        .spawn(move || {
            let result = std::panic::catch_unwind(|| {
                hash_password(variant, &password, m_cost, t_cost, p_cost)
            })
            .unwrap_or_else(|_| Err(format!("{} worker panicked", variant.name())));
            on_done();
            result
        })
}

/// Generates `len` cryptographically random bytes and returns them Base64-encoded.
pub fn hash_gen(len: usize) -> String {
    let mut bytes = vec![0u8; len];
    rand::fill(&mut bytes[..]);
    general_purpose::STANDARD.encode(&bytes)
}

/// Parses a decimal integer and checks that it lies within `min..=max`.
pub fn parse_bounded(text: &str, min: u32, max: u32) -> Result<u32, String> {
    let value = text
        .trim()
        .parse::<u32>()
        .map_err(|_| format!("'{text}' is not a valid number"))?;
    if (min..=max).contains(&value) {
        Ok(value)
    } else {
        Err(format!("{value} is out of range {min}..={max}"))
    }
}

pub fn form_log_string(s: &str) -> String {
    format!(
        "{s} - [{}]",
        offset::Local::now().time().format("%H:%M:%S.%3f")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use argon2::password_hash::{PasswordHash, PasswordVerifier};

    const M: u32 = 8;
    const T: u32 = 1;
    const P: u32 = 1;

    fn verify(phc: &str, password: &str) -> bool {
        let parsed = PasswordHash::new(phc).expect("valid PHC string");
        Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok()
    }

    // --- argon2 ---

    #[test]
    fn argon2i_hash_has_argon2i_prefix_and_params() {
        let h = hash_password_argon2i("secret", M, T, P).unwrap();
        assert!(h.starts_with("$argon2i$v=19$m=8,t=1,p=1$"), "got: {h}");
    }

    #[test]
    fn argon2id_hash_has_argon2id_prefix() {
        let h = hash_password_argon2id("secret", M, T, P).unwrap();
        assert!(h.starts_with("$argon2id$v=19$m=8,t=1,p=1$"), "got: {h}");
    }

    #[test]
    fn argon2i_hash_verifies_correct_password_only() {
        let h = hash_password_argon2i("secret", M, T, P).unwrap();
        assert!(verify(&h, "secret"));
        assert!(!verify(&h, "wrong"));
    }

    #[test]
    fn argon2id_hash_verifies_correct_password_only() {
        let h = hash_password_argon2id("secret", M, T, P).unwrap();
        assert!(verify(&h, "secret"));
        assert!(!verify(&h, "Secret"));
        assert!(!verify(&h, "secret "));
    }

    #[test]
    fn argon2_hashes_unicode_and_empty_passwords() {
        for pw in ["", "пароль", "Γεια σας", "🔑🔑", "a\0b"] {
            let h = hash_password_argon2id(pw, M, T, P).unwrap();
            assert!(verify(&h, pw), "failed for {pw:?}");
        }
    }

    #[test]
    fn argon2_hashes_long_password() {
        let pw = "x".repeat(10_000);
        let h = hash_password_argon2id(&pw, M, T, P).unwrap();
        assert!(verify(&h, &pw));
    }

    #[test]
    fn argon2_encodes_requested_params() {
        let h = hash_password_argon2id("pw", 64, 2, 4).unwrap();
        let parsed = PasswordHash::new(&h).unwrap();
        let params = Params::try_from(&parsed).unwrap();
        assert_eq!(params.m_cost(), 64);
        assert_eq!(params.t_cost(), 2);
        assert_eq!(params.p_cost(), 4);
        assert_eq!(parsed.version, Some(0x13));
    }

    #[test]
    fn argon2_salt_is_16_bytes() {
        let h = hash_password_argon2id("pw", M, T, P).unwrap();
        let parsed = PasswordHash::new(&h).unwrap();
        let mut buf = [0u8; 64];
        let salt = parsed.salt.unwrap().decode_b64(&mut buf).unwrap();
        assert_eq!(salt.len(), SALT_LEN);
    }

    #[test]
    fn argon2_output_is_32_bytes() {
        let h = hash_password_argon2i("pw", M, T, P).unwrap();
        let parsed = PasswordHash::new(&h).unwrap();
        assert_eq!(parsed.hash.unwrap().len(), Params::DEFAULT_OUTPUT_LEN);
    }

    #[test]
    fn argon2i_successive_hashes_differ_due_to_salt() {
        assert_ne!(
            hash_password_argon2i("secret", M, T, P).unwrap(),
            hash_password_argon2i("secret", M, T, P).unwrap()
        );
    }

    #[test]
    fn argon2id_and_argon2i_hashes_are_not_interchangeable() {
        let id = hash_password_argon2id("secret", M, T, P).unwrap();
        let i = hash_password_argon2i("secret", M, T, P).unwrap();
        assert_ne!(id.split('$').nth(1), i.split('$').nth(1));
    }

    #[test]
    fn argon2_invalid_params_return_error_instead_of_panicking() {
        // t = 0 is invalid
        assert!(hash_password_argon2id("pw", M, 0, P).is_err());
        // p = 0 is invalid
        assert!(hash_password_argon2i("pw", M, T, 0).is_err());
        // m must be at least 8 * p
        assert!(hash_password_argon2id("pw", 8, T, 2).is_err());
        assert!(hash_password_argon2id("pw", 16, T, 2).is_ok());
    }

    #[test]
    fn ui_extreme_params_are_valid_for_argon2() {
        // Smallest m combined with the largest p must still satisfy m >= 8 * p.
        assert!(Params::new(ARGON2_M_MIN, ARGON2_T_MIN, ARGON2_P_MAX, None).is_ok());
        assert!(Params::new(ARGON2_M_MAX, ARGON2_T_MAX, ARGON2_P_MIN, None).is_ok());
    }

    // --- hash_password / spawn_hash ---

    #[test]
    fn hash_password_dispatches_on_variant() {
        let id = hash_password(Argon2Variant::Id, "pw", M, T, P).unwrap();
        let i = hash_password(Argon2Variant::I, "pw", M, T, P).unwrap();
        assert!(id.starts_with("$argon2id$"), "got: {id}");
        assert!(i.starts_with("$argon2i$"), "got: {i}");
        assert!(verify(&id, "pw") && verify(&i, "pw"));
    }

    #[test]
    fn hash_password_error_names_variant() {
        let err = hash_password(Argon2Variant::I, "pw", M, 0, P).unwrap_err();
        assert!(err.starts_with("Argon2i error:"), "got: {err}");
    }

    #[test]
    fn spawn_hash_returns_result_and_calls_on_done() {
        use std::sync::mpsc;
        let (tx, rx) = mpsc::channel();
        let handle = spawn_hash(Argon2Variant::Id, "pw".into(), M, T, P, move || {
            tx.send(()).unwrap();
        })
        .unwrap();
        rx.recv_timeout(std::time::Duration::from_secs(30))
            .expect("on_done was not called");
        let h = handle.join().unwrap().unwrap();
        assert!(verify(&h, "pw"));
    }

    #[test]
    fn spawn_hash_reports_errors_and_still_calls_on_done() {
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        };
        let called = Arc::new(AtomicBool::new(false));
        let flag = called.clone();
        let handle = spawn_hash(Argon2Variant::I, "pw".into(), M, T, 0, move || {
            flag.store(true, Ordering::SeqCst);
        })
        .unwrap();
        assert!(handle.join().unwrap().is_err());
        assert!(called.load(Ordering::SeqCst));
    }

    #[test]
    fn spawn_hash_runs_off_the_calling_thread() {
        use std::sync::mpsc;
        let caller = std::thread::current().id();
        let (tx, rx) = mpsc::channel();
        let handle = spawn_hash(Argon2Variant::Id, "pw".into(), M, T, P, move || {
            tx.send(std::thread::current().id()).unwrap();
        })
        .unwrap();
        assert_ne!(rx.recv().unwrap(), caller);
        handle.join().unwrap().unwrap();
    }

    // --- hash_gen ---

    #[test]
    fn hash_gen_output_length_matches_base64_of_requested_bytes() {
        for byte_count in [1usize, 2, 3, 8, 16, 32, 64, 128, 255, 256, 1024] {
            assert_eq!(
                hash_gen(byte_count).len(),
                byte_count.div_ceil(3) * 4,
                "wrong length for byte_count={byte_count}"
            );
        }
    }

    #[test]
    fn hash_gen_decodes_to_requested_byte_count() {
        for byte_count in [KEY_LEN_MIN as usize, 32, KEY_LEN_MAX as usize] {
            let decoded = general_purpose::STANDARD
                .decode(hash_gen(byte_count))
                .unwrap();
            assert_eq!(decoded.len(), byte_count);
        }
    }

    #[test]
    fn hash_gen_supports_ui_maximum_of_256_bytes() {
        // Regression: 256 used to be parsed as u8 and panic.
        assert_eq!(hash_gen(KEY_LEN_MAX as usize).len(), 344);
    }

    #[test]
    fn hash_gen_zero_bytes_returns_empty_string() {
        assert_eq!(hash_gen(0), "");
    }

    #[test]
    fn hash_gen_successive_calls_are_not_identical() {
        // Fails with probability 2^-256 for 32-byte keys — negligible.
        assert_ne!(hash_gen(32), hash_gen(32));
    }

    #[test]
    fn hash_gen_output_is_valid_base64() {
        let out = hash_gen(32);
        assert!(
            general_purpose::STANDARD.decode(&out).is_ok(),
            "output is not valid base64: {out}"
        );
    }

    #[test]
    fn hash_gen_bytes_are_not_constant() {
        // Sanity check against a broken RNG returning a single repeated byte.
        let decoded = general_purpose::STANDARD.decode(hash_gen(256)).unwrap();
        assert!(decoded.iter().any(|&b| b != decoded[0]));
    }

    // --- parse_bounded ---

    #[test]
    fn parse_bounded_accepts_values_in_range() {
        assert_eq!(parse_bounded("8", 8, 256), Ok(8));
        assert_eq!(parse_bounded("256", 8, 256), Ok(256));
        assert_eq!(parse_bounded(" 32 ", 8, 256), Ok(32));
    }

    #[test]
    fn parse_bounded_rejects_out_of_range() {
        assert!(parse_bounded("7", 8, 256).is_err());
        assert!(parse_bounded("257", 8, 256).is_err());
        assert!(parse_bounded("0", 1, 100).is_err());
    }

    #[test]
    fn parse_bounded_rejects_garbage() {
        for s in ["", "abc", "-1", "1.5", "4294967296", "1e3", "0x10"] {
            assert!(parse_bounded(s, 0, u32::MAX).is_err(), "accepted {s:?}");
        }
    }

    #[test]
    fn parse_bounded_error_mentions_value() {
        let err = parse_bounded("999", 1, 100).unwrap_err();
        assert!(err.contains("999") && err.contains("100"), "got: {err}");
    }

    // --- form_log_string ---

    #[test]
    fn form_log_string_starts_with_input() {
        let result = form_log_string("hello");
        assert!(result.starts_with("hello"), "got: {result}");
    }

    #[test]
    fn form_log_string_contains_separator_and_closing_bracket() {
        let result = form_log_string("msg");
        assert!(result.contains(" - ["), "missing separator: {result}");
        assert!(result.ends_with(']'), "missing closing bracket: {result}");
    }

    #[test]
    fn form_log_string_timestamp_has_expected_format() {
        let result = form_log_string("x");
        let ts = &result["x - [".len()..result.len() - 1];
        // HH:MM:SS.mmm
        assert_eq!(ts.len(), 12, "got: {ts}");
        let b = ts.as_bytes();
        assert_eq!((b[2], b[5], b[8]), (b':', b':', b'.'), "got: {ts}");
        assert!(
            ts.chars().filter(|c| c.is_ascii_digit()).count() == 9,
            "got: {ts}"
        );
    }

    #[test]
    fn form_log_string_handles_non_ascii() {
        let result = form_log_string("Γεια σας!");
        assert!(result.starts_with("Γεια σας! - ["), "got: {result}");
    }

    #[test]
    fn form_log_string_empty_input_still_produces_timestamp() {
        let result = form_log_string("");
        assert!(result.starts_with(" - ["));
        assert!(result.ends_with(']'));
    }
}
