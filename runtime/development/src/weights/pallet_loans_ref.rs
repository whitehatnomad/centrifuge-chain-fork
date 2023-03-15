
//! Autogenerated weights for `pallet_loans_ref`
//!
//! THIS FILE WAS AUTO-GENERATED USING THE SUBSTRATE BENCHMARK CLI VERSION 4.0.0-dev
//! DATE: 2023-03-09, STEPS: `2`, REPEAT: 1, LOW RANGE: `[]`, HIGH RANGE: `[]`
//! HOSTNAME: `MBP-de-Luis.home`, CPU: `<UNKNOWN>`
//! EXECUTION: None, WASM-EXECUTION: Compiled, CHAIN: Some("development"), DB CACHE: 1024

// Executed Command:
// target/release/centrifuge-chain
// benchmark
// pallet
// --pallet=pallet-loans
// --chain
// development
// --extrinsic=*
// --output=runtime/development/src/weights/pallet_loans_ref.rs

#![cfg_attr(rustfmt, rustfmt_skip)]
#![allow(unused_parens)]
#![allow(unused_imports)]

use frame_support::{traits::Get, weights::Weight};
use sp_std::marker::PhantomData;

/// Weight functions for `pallet_loans_ref`.
pub struct WeightInfo<T>(PhantomData<T>);
impl<T: frame_system::Config> pallet_loans_ref::WeightInfo for WeightInfo<T> {
	fn update_portfolio_valuation(n: u32) -> Weight {
		Weight::from_ref_time(31_740_408) // Standard Error: 4_421
			.saturating_add(Weight::from_ref_time(5_889_944).saturating_mul(n as u64))
			.saturating_add(T::DbWeight::get().reads(4 as u64))
			.saturating_add(T::DbWeight::get().writes(1 as u64))
	}

	fn create() -> Weight {
		Weight::from_ref_time(55_000_000)
			.saturating_add(T::DbWeight::get().reads(6 as u64))
			.saturating_add(T::DbWeight::get().writes(6 as u64))
	}

	fn borrow(n: u32) -> Weight {
		Weight::from_ref_time(89_980_992) // Standard Error: 6_031
			.saturating_add(Weight::from_ref_time(339_355).saturating_mul(n as u64))
			.saturating_add(T::DbWeight::get().reads(9 as u64))
			.saturating_add(T::DbWeight::get().writes(7 as u64))
	}

	fn repay(n: u32) -> Weight {
		Weight::from_ref_time(88_057_556) // Standard Error: 9_218
			.saturating_add(Weight::from_ref_time(296_755).saturating_mul(n as u64))
			.saturating_add(T::DbWeight::get().reads(8 as u64))
			.saturating_add(T::DbWeight::get().writes(5 as u64))
	}

	fn write_off(n: u32) -> Weight {
		Weight::from_ref_time(50_179_983) // Standard Error: 1_760
			.saturating_add(Weight::from_ref_time(299_592).saturating_mul(n as u64))
			.saturating_add(T::DbWeight::get().reads(5 as u64))
			.saturating_add(T::DbWeight::get().writes(3 as u64))
	}

	fn admin_write_off(n: u32) -> Weight {
		Weight::from_ref_time(63_153_708) // Standard Error: 2_472
			.saturating_add(Weight::from_ref_time(325_868).saturating_mul(n as u64))
			.saturating_add(T::DbWeight::get().reads(6 as u64))
			.saturating_add(T::DbWeight::get().writes(3 as u64))
	}

	fn close(n: u32) -> Weight {
		Weight::from_ref_time(55_882_678) // Standard Error: 7_625
			.saturating_add(Weight::from_ref_time(338_879).saturating_mul(n as u64))
			.saturating_add(T::DbWeight::get().reads(5 as u64))
			.saturating_add(T::DbWeight::get().writes(7 as u64))
	}

	fn update_write_off_policy() -> Weight {
		Weight::from_ref_time(27_000_000)
			.saturating_add(T::DbWeight::get().reads(2 as u64))
			.saturating_add(T::DbWeight::get().writes(1 as u64))
	}
}
