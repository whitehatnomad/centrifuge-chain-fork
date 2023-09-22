// Copyright 2021 Centrifuge Foundation (centrifuge.io).
//
// This file is part of the Centrifuge chain project.
// Centrifuge is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version (see http://www.gnu.org/licenses).
// Centrifuge is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
use crate::{Investments, PoolSystem, Runtime, Weight};

pub type UpgradeCentrifuge1021 = anemoy_pool::Migration;

/// Migrate the Anemoy Pool's currency from LpEthUSC to Circle's USDC,
/// native on Polkadot's AssetHub.
mod anemoy_pool {

	use cfg_primitives::{PoolId, TrancheId};
	use cfg_types::{
		orders::TotalOrder,
		tokens::{CurrencyId, TrancheCurrency},
	};
	#[cfg(feature = "try-runtime")]
	use codec::{Decode, Encode};
	#[cfg(feature = "try-runtime")]
	use frame_support::ensure;
	use frame_support::traits::OnRuntimeUpgrade;
	#[cfg(feature = "try-runtime")]
	use pallet_pool_system::PoolDetailsOf;
	#[cfg(feature = "try-runtime")]
	use sp_std::vec::Vec;

	use super::*;

	const ANEMOY_POOL_ID: PoolId = 4_139_607_887;
	#[cfg(feature = "try-runtime")]
	const LP_ETH_USDC: CurrencyId = CurrencyId::ForeignAsset(100_001);
	const DOT_NATIVE_USDC: CurrencyId = CurrencyId::ForeignAsset(6);

	pub struct Migration;

	impl OnRuntimeUpgrade for Migration {
		#[cfg(feature = "try-runtime")]
		fn pre_upgrade() -> Result<Vec<u8>, &'static str> {
			let pool_details: PoolDetailsOf<Runtime> =
				PoolSystem::pool(ANEMOY_POOL_ID).ok_or("Could not find Anemoy Pool")?;

			ensure!(
				pool_details.currency == LP_ETH_USDC,
				"anemoy_pool::Migration: pre_upgrade failing as Anemoy's currency should be LpEthUSDC"
			);

			Ok(pool_details.encode())
		}

		fn on_runtime_upgrade() -> Weight {
			// To be executed at 1021, reject higher spec_versions
			if crate::VERSION.spec_version >= 1022 {
				log::info!(
					"anemoy_pool::Migration: NOT execution since VERSION.spec_version >= 1022"
				);
				return Weight::zero();
			}

			pallet_pool_system::Pool::<Runtime>::mutate(ANEMOY_POOL_ID, |details| {
				let details = details.as_mut().unwrap();
				details.currency = DOT_NATIVE_USDC;
				log::info!("anemoy_pool::Migration: Finished mutating currency to USDC");
			});

			<Runtime as frame_system::Config>::DbWeight::get().reads_writes(1, 1)
		}

		#[cfg(feature = "try-runtime")]
		fn post_upgrade(old_state: Vec<u8>) -> Result<(), &'static str> {
			let mut old_pool_details = PoolDetailsOf::<Runtime>::decode(&mut old_state.as_ref())
				.map_err(|_| "Error decoding pre-upgrade state")?;

			let pool_details: PoolDetailsOf<Runtime> =
				PoolSystem::pool(ANEMOY_POOL_ID).ok_or("Could not find Anemoy Pool")?;

			// Ensure the currency set to USDC is the only mutation performed
			old_pool_details.currency = DOT_NATIVE_USDC;
			ensure!(
				old_pool_details == pool_details,
				"Corrupted migration: Only the currency of the Anemoy pool should have changed"
			);

			log::info!("anemoy_pool::Migration: post_upgrade succeeded");
			Ok(())
		}
	}

	// todo(nuno): also check that pool value is 0 and check also that
	// Investments::InvestOrders and Investments::RedeemOrder have no entries from
	// Anemoy; the latter ones seem tricky at first sight since they are double maps
	// first keyed by an AccountId, meaning we need to transverse that first which
	// is more costly.
	fn sanity_checks(tranche_id: TrancheId) -> bool {
		let tc = TrancheCurrency {
			pool_id: ANEMOY_POOL_ID,
			tranche_id,
		};

		Investments::acc_active_invest_order(tc) == TotalOrder::default()
			&& Investments::acc_active_redeem_order(tc) == TotalOrder::default()
	}
}
