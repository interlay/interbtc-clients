use parity_scale_codec::{Codec, EncodeLike};
use sp_runtime::traits::{AtLeast32Bit, Member};
use substrate_subxt::system::{System, SystemEventsDecoder};
use substrate_subxt_proc_macro::module;

#[module]
pub trait Timestamp: System {
    /// Type used for expressing timestamp.
    type Moment: Codec + AtLeast32Bit + EncodeLike + Member + Default;
}
