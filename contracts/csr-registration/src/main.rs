#![cfg_attr(not(any(feature = "library", test)), no_std)]
#![cfg_attr(not(test), no_main)]

#[cfg(any(feature = "library", test))]
extern crate alloc;

#[path = "registration.rs"]
mod registration;

use ckb_std::ckb_constants::Source;
use ckb_std::ckb_types::prelude::*;
use ckb_std::error::SysError;
use ckb_std::high_level::{load_cell_data, load_cell_lock, load_script};
use registration::{check_output, LockInfo};

#[cfg(not(any(feature = "library", test)))]
ckb_std::entry!(program_entry);
#[cfg(not(any(feature = "library", test)))]
ckb_std::default_alloc!(16384, 1258306, 64);

/// Error codes: 1–9 syscall problems, 10+ see registration::Error.
const ERR_SYSCALL: i8 = 1;

pub fn program_entry() -> i8 {
    match run() {
        Ok(()) => 0,
        Err(code) => code,
    }
}

fn run() -> Result<(), i8> {
    let script = load_script().map_err(|_| ERR_SYSCALL)?;
    let args = script.args().raw_data();
    // Every registration cell created or updated in this transaction must be valid.
    // Spending (destroying) a registration needs nothing extra: the sighash lock
    // already requires the service key's signature.
    let mut index = 0;
    loop {
        let data = match load_cell_data(index, Source::GroupOutput) {
            Ok(d) => d,
            Err(SysError::IndexOutOfBound) => break,
            Err(_) => return Err(ERR_SYSCALL),
        };
        let lock = load_cell_lock(index, Source::GroupOutput).map_err(|_| ERR_SYSCALL)?;
        let code_hash = lock.code_hash();
        let lock_args = lock.args().raw_data();
        let info = LockInfo {
            code_hash: code_hash.as_slice(),
            hash_type: lock.hash_type().as_slice()[0],
            args: &lock_args,
        };
        check_output(&args, &data, &info).map_err(|e| e as i8)?;
        index += 1;
    }
    Ok(())
}
