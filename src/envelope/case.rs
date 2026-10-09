//! GENERATE — one test case from its seed. NOT measured.
//!
//! The stage's input is the ciphertext CoeffsToSlots receives inside a
//! bootstrap: the raised one. It is made here the way the orchestrator makes
//! it — encrypt the message at the input layout, SlotsToCoeffs, ModUp — with
//! the message, its encryption mask and error all derived from the case's
//! seed, so a case is its seed. The two stages before this one are run by
//! the reference code below, byte for byte what `ckks_bootstrap` does before
//! its CoeffsToSlots (`ckks_bootstrap_s2c_mod_up` in Poulpy). The
//! specification's file, laid over every submission.

use poulpy_ckks::api::{CKKSCopyOps, CKKSDFTOps, CKKSEncodingHostOps, CKKSEncryptOps, CKKSPow2Ops};
use poulpy_ckks::layouts::{BootstrappingKeys, CKKSModuleAlloc};
use poulpy_ckks::oep::CKKSEncapsulatedModUpImpl;
use poulpy_ckks::{CKKSInfos, CKKSMeta, SetCKKSInfos};
use poulpy_core::layouts::prepared::GGLWEPreparedToBackendRef;
use poulpy_core::layouts::LWEInfos;
use poulpy_hal::api::ScratchOwnedBorrow;
use poulpy_hal::source::Source;

use crate::envelope::backend::BE;
use crate::fherma::Inputs;

use super::keys::{seed32, Context, Ct};

/// One test case from its input — the signature's `Inputs`, one seed: the
/// message encrypted at the preset's input layout, then the two stages that
/// precede CoeffsToSlots in the S2C-first pipeline. What `check` measures
/// the output against — the coefficients the raised ciphertext carries,
/// integer parts `I(X)·q` included — it reads from that ciphertext with the
/// secret.
pub fn generate(state: &Context, input: &Inputs) -> Ct {
    let fresh = encrypt(state, input.case_seed);
    let coeffs = slots_to_coeffs(state, &fresh);
    mod_up(state, &coeffs)
}

/// The bootstrapping's own input: the message on the unit disc, encoded and
/// encrypted at the input layout — the same bytes the bootstrapping reference
/// makes for this seed.
pub fn encrypt(state: &Context, seed: u64) -> Ct {
    let (re, im) = sample_unit_disc(seed, state.preset.n() / 2);

    let mut pt = state
        .module
        .ckks_pt_vec_alloc(state.preset.base2k().into(), state.input_layout.k());
    pt.set_meta(state.input_layout.meta());
    let mut arena = state.scratch.borrow_mut();
    state
        .module
        .ckks_encode_reim_into(&mut pt, &re, &im, &mut arena.borrow())
        .expect("encode the case message");

    // 0.9.0 samples the mask and the Gaussian noise at the ciphertext's own
    // width, so the encryption layout is no longer the caller's to pass.
    let mut ct = state.module.ckks_ciphertext_alloc_from_glwe_infos(&state.input_layout);
    let mut xa = Source::new(seed32(seed, "input-xa"));
    let mut xe = Source::new(seed32(seed, "input-xe"));
    state
        .module
        .ckks_encrypt_sk(
            &mut ct,
            &pt,
            &state.sk,
            &mut xe,
            &mut xa,
            &mut arena.borrow(),
        )
        .expect("encrypt the case input");
    ct
}

/// Stage 1 of the S2C-first pipeline: the slots to the coefficients. A copy
/// doubled first — the split decode matrix reconstructs `2·ct`, and the
/// orchestrator keeps that normalisation — then the homomorphic decode DFT.
pub fn slots_to_coeffs(state: &Context, fresh: &Ct) -> Ct {
    let mut ct = state.module.ckks_ciphertext_alloc_from_glwe_infos(&state.input_layout);
    let mut arena = state.scratch.borrow_mut();
    let mut scratch = arena.borrow();
    state.module.ckks_copy(&mut ct, fresh, &mut scratch).expect("copy the input");
    state
        .module
        .ckks_mul_pow2_assign(&mut ct, 1, &mut scratch)
        .expect("double the input");
    state
        .module
        .ckks_dft_evaluate_assign(
            &mut ct,
            state.context.slots_to_coeffs(),
            state.keys.rotation_keys(),
            &mut scratch,
        )
        .expect("SlotsToCoeffs");
    ct
}

/// Stage 2: ModUp with sparse-secret encapsulation — switch to the sparse
/// secret, raise the modulus to the bootstrap width, switch back — with the
/// C2S guard bits fused into the raise, then the raised metadata. This is the
/// S2C-first raise (`lift = None`, `scale_up = c2s_guard_bits`), not the
/// C2S-first one `ckks_bootstrap_mod_up` computes from the EvalMod plan.
pub fn mod_up(state: &Context, coeffs: &Ct) -> Ct {
    let guard = state.context.c2s_guard_bits();
    let log_modulus_in = coeffs.k().as_usize();
    let (d2s, s2d) = state
        .keys
        .encapsulation_keys()
        .expect("the preset encapsulates the raise in a sparse secret");

    let mut src = state.module.ckks_ciphertext_alloc_from_glwe_infos(&state.input_layout);
    let mut raised = state
        .module
        .ckks_ciphertext_alloc_from_glwe_infos(&state.preset.bootstrap_layout());
    let mut arena = state.scratch.borrow_mut();
    let mut scratch = arena.borrow();
    state.module.ckks_copy(&mut src, coeffs, &mut scratch).expect("copy the coefficients");
    <BE as CKKSEncapsulatedModUpImpl>::ckks_encapsulated_mod_up(
        &state.module,
        &mut raised,
        &mut src,
        guard,
        &d2s.to_backend_ref(),
        &s2d.to_backend_ref(),
        &mut scratch,
    )
    .expect("ModUp");
    raised.set_meta(CKKSMeta {
        log_sparsity: coeffs.log_sparsity(),
        log_delta: log_modulus_in + guard,
        slots: coeffs.slots(),
    });
    raised
}

/// `m` complex values uniform on the unit disc, from the case-seed: SplitMix64
/// over a per-case root, points drawn uniformly in the square and kept when
/// inside the disc. Only multiplication and comparison — no libm, so the same
/// seed gives the same f64 message bit-for-bit on any platform.
fn sample_unit_disc(seed: u64, m: usize) -> (Vec<f64>, Vec<f64>) {
    let mut state = u64::from_le_bytes(seed32(seed, "msg")[..8].try_into().unwrap());
    let mut next = || -> f64 {
        state = state.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^= z >> 31;
        (z >> 11) as f64 / (1u64 << 52) as f64 - 1.0 // in [-1, 1)
    };
    let (mut re, mut im) = (Vec::with_capacity(m), Vec::with_capacity(m));
    while re.len() < m {
        let (x, y) = (next(), next());
        if x * x + y * y < 1.0 {
            re.push(x);
            im.push(y);
        }
    }
    (re, im)
}
