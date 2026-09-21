//! INIT — your setup. Over the point and the context, never a case. NOT
//! measured.
//!
//! The reference's: allocate the two output halves and a working arena. A
//! submission with a GPU would move the rotation keys to the card here;
//! nothing computed here may depend on a case, and the loop never shows it
//! one. (`threads` in `config.jsonc` is read by the envelope's `setup`: the
//! pool is built once, before keygen.)

use poulpy_ckks::layouts::CKKSModuleAlloc;
use poulpy_hal::api::ScratchOwnedAlloc;
use poulpy_hal::layouts::ScratchOwned;

use crate::envelope::backend::BE;
use crate::envelope::{Context, Output};
use crate::fherma::Point;

/// Whatever `init` prepares and `run` needs.
pub struct State<'a> {
    pub context: &'a Context,
    /// Preallocated outputs; `run` writes into them (as Poulpy's driver does).
    /// Both at the bootstrap layout: CoeffsToSlots leaves them at what the
    /// raised width minus its own consumption is.
    pub output: Output,
    pub scratch: ScratchOwned<BE>,
}

pub fn init<'a>(point: &Point, context: &'a Context, config: &str) -> State<'a> {
    let _ = (point, config);
    let layout = context.preset.bootstrap_layout();
    State {
        context,
        output: Output {
            re: context.module.ckks_ciphertext_alloc_from_glwe_infos(&layout),
            im: context.module.ckks_ciphertext_alloc_from_glwe_infos(&layout),
        },
        scratch: ScratchOwned::<BE>::alloc(context.scratch_bytes),
    }
}
