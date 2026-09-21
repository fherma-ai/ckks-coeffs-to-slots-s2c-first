//! CHECK — the output's precision against what the stage was given. NOT
//! measured as score; timed apart and reported as metrics.
//!
//! Correctness on the platform is the digest. This is the other reading of a
//! CoeffsToSlots: how faithfully the coefficients of the raised ciphertext —
//! integer parts `I(X)·q` included, exactly what EvalMod will see — arrive in
//! the slots. The same measurement as Poulpy's own stage test
//! (`test_suite::bootstrapping`, `C2S-PREC`): decrypt the input to its
//! coefficients, decrypt each half to its slots, and take the scale-invariant
//! signal-to-noise ratio in bits between slot `j` and coefficient `bitrev(j)`
//! (the real half against the first `N/2` coefficients, the imaginary half
//! against the second). The platform owns this file; it has the secret
//! because `init` does.

use poulpy_ckks::api::{CKKSDecryptOps, CKKSEncodingHostOps};
use poulpy_ckks::layouts::{CKKSModuleAlloc, CKKSPlaintextVecHostCodec};
use poulpy_ckks::{CKKSInfos, CKKSMeta, SetCKKSInfos, SlotsKind};
use poulpy_core::layouts::{GLWESecretPrepared, LWEInfos};
use poulpy_hal::api::ScratchOwnedBorrow;
use poulpy_hal::layouts::{Backend, Module, ScratchArena};

use crate::envelope::backend::BE;

use super::keys::{Context, Ct};

/// Plaintext budget bits above `log_delta` a ciphertext is decrypted at, as
/// in Poulpy's driver.
const LOG_BUDGET: usize = 8;

/// Signal-to-noise ratio in bits of each half: how many bits of the
/// coefficients survived the transform.
#[derive(Clone, Copy, Debug)]
pub struct Precision {
    pub re_snr_bits: f64,
    pub im_snr_bits: f64,
}

/// Decrypts the two halves and measures them against the coefficients of
/// the case's input.
pub fn precision(state: &Context, input: &Ct, re: &Ct, im: &Ct) -> Precision {
    let coeffs = coefficients(state, input);
    let m = coeffs.len() / 2;
    let bits = m.trailing_zeros() as usize;
    let (mut want_re, mut want_im) = (vec![0f64; m], vec![0f64; m]);
    for j in 0..m {
        let b = bitrev(j, bits);
        want_re[j] = coeffs[b];
        want_im[j] = coeffs[m + b];
    }

    let mut arena = state.scratch.borrow_mut();
    let got_re = real_slots(&state.module, &mut arena.borrow(), &state.sk, re, m);
    let got_im = real_slots(&state.module, &mut arena.borrow(), &state.sk, im, m);
    Precision {
        re_snr_bits: snr_bits(&got_re, &want_re),
        im_snr_bits: snr_bits(&got_im, &want_im),
    }
}

/// The coefficients a ciphertext encrypts, as floats at its scale.
fn coefficients(state: &Context, ct: &Ct) -> Vec<f64> {
    let (log_delta, log_budget) = budget(ct);
    let mut pt = state
        .module
        .ckks_pt_vec_alloc(ct.base2k(), (log_delta + log_budget).into());
    pt.set_meta(CKKSMeta {
        log_sparsity: 0,
        log_delta,
        slots: SlotsKind::Complex,
    });
    let mut arena = state.scratch.borrow_mut();
    state
        .module
        .ckks_decrypt(&mut pt, ct, &state.sk, &mut arena.borrow())
        .expect("decrypt the input for the precision check");
    let mut coeffs = vec![0f64; ct.n().as_usize()];
    pt.decode_host_floats(&mut coeffs)
        .expect("read the input's coefficients for the precision check");
    coeffs
}

/// The real part of every slot of one output half.
fn real_slots(
    module: &Module<BE>,
    scratch: &mut ScratchArena<'_, BE>,
    sk: &GLWESecretPrepared<<BE as Backend>::OwnedBuf, BE>,
    ct: &Ct,
    m: usize,
) -> Vec<f64> {
    let (log_delta, log_budget) = budget(ct);
    let mut pt = module.ckks_pt_vec_alloc(ct.base2k(), (log_delta + log_budget).into());
    pt.set_meta(CKKSMeta {
        log_sparsity: 0,
        log_delta,
        slots: SlotsKind::Complex,
    });
    module
        .ckks_decrypt(&mut pt, ct, sk, scratch)
        .expect("decrypt a half for the precision check");
    let (mut re, mut im) = (vec![0f64; m], vec![0f64; m]);
    module
        .ckks_decode_reim_into(&pt, &mut re, &mut im, scratch)
        .expect("decode a half for the precision check");
    re
}

/// `(log_delta, log_budget)` to decrypt at: a small budget above the scale,
/// capped so `log_delta + log_budget <= 127` fits the decode codec.
fn budget(ct: &Ct) -> (usize, usize) {
    let log_delta = ct.log_delta();
    let log_budget = ct
        .log_budget()
        .min(LOG_BUDGET)
        .min(127usize.saturating_sub(log_delta));
    (log_delta, log_budget)
}

/// Bit-reversal of `j` over `bits` bits: Poulpy's slot-to-coefficient order.
fn bitrev(j: usize, bits: usize) -> usize {
    ((j as u32).reverse_bits() >> (u32::BITS - bits as u32)) as usize
}

/// Scale-invariant signal-to-noise ratio in bits, Poulpy's `snr_bits`: the
/// best global scale `s` between `got` and `want`, then
/// `-0.5·log2(||got − s·want||² / ||s·want||²)`. Measures how well the shape
/// is recovered, whatever the per-step scale bookkeeping.
fn snr_bits(got: &[f64], want: &[f64]) -> f64 {
    let dot_gw: f64 = got.iter().zip(want).map(|(g, w)| g * w).sum();
    let dot_ww: f64 = want.iter().map(|w| w * w).sum();
    let s = if dot_ww > 0.0 { dot_gw / dot_ww } else { 0.0 };
    let err2: f64 = got.iter().zip(want).map(|(g, w)| (g - s * w).powi(2)).sum();
    let sig2: f64 = want.iter().map(|w| (s * w).powi(2)).sum();
    if err2 <= 0.0 || sig2 <= 0.0 {
        return f64::INFINITY;
    }
    -0.5 * (err2 / sig2).log2()
}
