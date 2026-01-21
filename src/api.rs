use crate::{DerivationIndex, DerivationScheme, Signature, XPrv};

pub type BIP44Path = [DerivationIndex; 5];

pub enum KeyContext {
    Address,
    Identity,
}

impl KeyContext {
    pub fn coin_type(&self) -> DerivationIndex {
        match self {
            KeyContext::Address => 283,
            KeyContext::Identity => 0,
        }
    }
}

const HARDENED_OFFSET: u32 = 0x80_00_00_00;

pub fn harden(index: DerivationIndex) -> DerivationIndex {
    index + HARDENED_OFFSET
}

fn derive_path(root_xprv: &XPrv, path: &[DerivationIndex], scheme: DerivationScheme) -> XPrv {
    let mut current_xprv = root_xprv.clone();
    for &index in path {
        current_xprv = current_xprv.derive(scheme, index);
    }
    current_xprv
}

pub fn key_gen(
    root_key: XPrv,
    context: KeyContext,
    account: DerivationIndex,
    key_index: DerivationIndex,
    scheme: DerivationScheme,
) -> XPrv {
    let bip44_path = [
        harden(44),
        harden(context.coin_type()),
        harden(account),
        0,
        key_index,
    ];

    derive_path(&root_key, &bip44_path, scheme)
}

pub fn raw_sign(
    root_key: &XPrv,
    bip44_path: &[DerivationIndex],
    data: &[u8],
    scheme: DerivationScheme,
) -> Vec<u8> {
    let derived_xprv = derive_path(root_key, bip44_path, scheme);
    let signature: Signature<Vec<u8>> = derived_xprv.sign(data);
    signature.to_bytes().to_vec()
}

pub fn sign(
    root_key: &XPrv,
    context: KeyContext,
    account: DerivationIndex,
    key_index: DerivationIndex,
    prefix_encoded_tx: &[u8],
    scheme: DerivationScheme,
) -> Vec<u8> {
    let bip44_path = [
        harden(44),
        harden(context.coin_type()),
        harden(account),
        0,
        key_index,
    ];

    raw_sign(root_key, &bip44_path, prefix_encoded_tx, scheme)
}
