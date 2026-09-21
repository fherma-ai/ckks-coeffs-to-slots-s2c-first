//! ENVELOPE — the specification's side of the measurement, laid over every
//! submission: what turns the point into a context, a case into the stage's
//! input, the output into bytes, and the output into a verdict's metrics.
//! Four functions and three types; the loop (`main.rs`, generated from the
//! signature) calls them around the author's `init` / `run` / `free`.
//!
//! The substance is in the submodules: `keys` (setup — the same keygen as the
//! bootstrapping's), `case` (generate: encrypt, SlotsToCoeffs, ModUp),
//! `bytes` (the canonical serialisation), `check` (precision against the
//! input's coefficients).

pub mod backend;
pub mod bytes;
pub mod case;
pub mod check;
pub mod keys;

use crate::fherma::{Inputs, Point};

pub use keys::{Context, Ct};

/// Discarded runs before the first timed one.
pub const WARMUP: usize = 3;

/// What `run` receives: the raised ciphertext.
pub type Input = Ct;

/// What `run` leaves: the two halves, real and imaginary — the signature's
/// `re` and `im`.
pub struct Output {
    pub re: Ct,
    pub im: Ct,
}

/// What `check` says of an output.
pub struct Check {
    pub valid: bool,
    pub metrics: Vec<(&'static str, f64)>,
    pub note: Option<String>,
}

/// The context from the point: keygen from `key_seed`, once. Not measured.
/// The worker pool of a `*-rayon` backend is sized here, from the solution's
/// `config.jsonc` (`threads`; 0 or absent is every core): it is built once
/// per process, before any work, and keygen is work.
pub fn setup(point: &Point, config: &str) -> Context {
    if backend::THREADED {
        backend::set_threads(threads(config));
    }
    Context::setup(point)
}

/// `threads` from `config.jsonc`; 0 or absent is every core.
fn threads(config: &str) -> usize {
    let all = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    let text: String = config
        .lines()
        .map(|line| line.split("//").next().unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n");
    text.find("\"threads\"")
        .and_then(|at| text[at..].find(':').map(|colon| at + colon + 1))
        .and_then(|from| {
            let rest = text[from..].trim_start();
            let end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
            rest[..end].parse::<usize>().ok()
        })
        .filter(|&t| t > 0)
        .unwrap_or(all)
}

/// Facts about the context, for the report's header.
pub fn describe(context: &Context) -> Vec<(&'static str, String)> {
    vec![
        ("preset", context.preset.name().to_string()),
        ("poulpy", keys::POULPY_VERSION.to_string()),
        ("backend", backend::NAME.to_string()),
    ]
}

/// The case from its inputs: the stage's input, made with the secret. Not measured.
pub fn generate(context: &Context, inputs: &Inputs) -> Input {
    case::generate(context, inputs)
}

/// The output as the bytes the platform hashes, one entry per result of the
/// signature, by name.
pub fn serialize(output: &Output) -> Vec<(&'static str, Vec<u8>)> {
    vec![("re", bytes::bytes(&output.re)), ("im", bytes::bytes(&output.im))]
}

/// Whether the output has the shape the stage leaves, and how many bits of
/// the input's coefficients reached the slots (Poulpy's `C2S-PREC`).
pub fn check(context: &Context, input: &Input, output: &Output) -> Check {
    use poulpy_ckks::CKKSInfos;
    use poulpy_core::layouts::{GLWEInfos, LWEInfos};

    // A half holds real values in its slots — the coefficients of one half
    // of the input — at the input's sparsity, narrower than the input by what
    // the transform consumed.
    let shaped = |half: &Ct| {
        half.n() == input.n()
            && half.rank() == input.rank()
            && half.base2k() == input.base2k()
            && half.slots() == poulpy_ckks::SlotsKind::Real
            && half.log_sparsity() == input.log_sparsity()
            && half.k().as_usize() > 0
            && half.k() < input.k()
    };
    let precision = check::precision(context, input, &output.re, &output.im);
    Check {
        valid: shaped(&output.re)
            && shaped(&output.im)
            && precision.re_snr_bits.is_finite()
            && precision.im_snr_bits.is_finite(),
        metrics: vec![
            ("snr_bits", precision.re_snr_bits.min(precision.im_snr_bits)),
            ("snr_bits_re", precision.re_snr_bits),
            ("snr_bits_im", precision.im_snr_bits),
        ],
        note: None,
    }
}
