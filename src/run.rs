//! RUN — the function under measurement. The loop times this call and
//! nothing else.
//!
//! Reference: Poulpy's `ckks_coeffs_to_slots_split` on the preset's compiled
//! CoeffsToSlots matrix and rotation keys — the homomorphic encode DFT that
//! moves the raised ciphertext's coefficients into the slots of two
//! ciphertexts, the real parts in one and the imaginary in the other. Then
//! the guard bits come off both halves' scale, as the orchestrator does
//! before it hands them to EvalMod (`ckks_bootstrap_coeffs_to_slots` in
//! Poulpy): that relabel is part of what the stage leaves behind.
//!
//! A submission with its own algorithm replaces the body of `run`. It gets
//! its state from `init` and the raised input, and must leave the same bytes
//! in the two halves as this reference does.

use poulpy_ckks::api::CKKSDFTOps;
use poulpy_ckks::layouts::BootstrappingKeys;
use poulpy_ckks::{CKKSInfos, SetCKKSInfos};
use poulpy_hal::api::ScratchOwnedBorrow;

use crate::envelope::{Input, Output};
use crate::init::State;

pub fn run<'a>(state: &'a mut State<'_>, input: &Input) -> &'a Output {
    let context = state.context;
    let State { output, scratch, .. } = state;

    // The stage consumes width: it starts at the bootstrap width and leaves
    // the halves narrower. The buffers are reused, so they are set back to
    // the full width before every run.
    let full = context.preset.bootstrap_k();
    output.re.set_k(full.into());
    output.im.set_k(full.into());
    context
        .module
        .ckks_coeffs_to_slots_split(
            &mut output.re,
            &mut output.im,
            input,
            context.context.coeffs_to_slots(),
            context.keys.rotation_keys(),
            &mut scratch.borrow(),
        )
        .expect("CoeffsToSlots");
    let guard = context.context.c2s_guard_bits();
    output.re.set_log_delta(output.re.log_delta() - guard);
    output.im.set_log_delta(output.im.log_delta() - guard);
    output
}
