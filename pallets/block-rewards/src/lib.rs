// Copyright 2021 Centrifuge Foundation (centrifuge.io).
// This file is part of Centrifuge chain project.

// Centrifuge is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version (see http://www.gnu.org/licenses).

// Centrifuge is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
//! # Rewards Pallet
//!
//! The Rewards pallet provides functionality for distributing rewards to
//! different accounts with different currencies.
//! The distribution happens when an epoch (a constant time interval) finalizes.
//! The user can stake an amount during one of more epochs to claim the reward.
//!
//! Rewards pallet can be configured with any implementation of [`cfg_traits::rewards`] traits
//! which gives the reward behavior.
//!
//! The Rewards pallet provides functions for:
//!
//! - Stake/Unstake a currency amount.
//! - Claim the reward given to a staked currency.
//! - Admin methods to configure epochs, currencies and reward groups.
//!
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;

pub mod weights;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;

pub use cfg_traits::{
	ops::{EnsureAdd, EnsureAddAssign},
	rewards::{AccountRewards, CurrencyGroupChange, DistributedRewards, GroupRewards},
};
use frame_support::{
	pallet_prelude::*,
	traits::tokens::{AssetId, Balance},
	DefaultNoBound,
};
pub use frame_support::{
	storage::{bounded_btree_map::BoundedBTreeMap, transactional},
	transactional,
};
use frame_system::pallet_prelude::*;
use num_traits::sign::Unsigned;
pub use pallet::*;
use pallet_session::Validators;
use sp_runtime::{traits::Zero, FixedPointOperand};
use sp_std::mem;
use weights::WeightInfo;

/// Type that contains the associated data of an epoch
#[derive(Encode, Decode, TypeInfo, MaxEncodedLen, RuntimeDebugNoBound)]
#[scale_info(skip_type_params(T))]
pub struct EpochData<T: Config> {
	duration: T::BlockNumber,
	reward: T::Balance,
	weights: BoundedBTreeMap<T::GroupId, T::Weight, T::MaxGroups>,
}

impl<T: Config> Default for EpochData<T> {
	fn default() -> Self {
		Self {
			duration: T::InitialEpochDuration::get(),
			reward: T::Balance::zero(),
			weights: BoundedBTreeMap::default(),
		}
	}
}

/// Type that contains the pending update.
#[derive(
	PartialEq, Clone, DefaultNoBound, Encode, Decode, TypeInfo, MaxEncodedLen, RuntimeDebugNoBound,
)]
#[scale_info(skip_type_params(T))]
pub struct EpochChanges<T: Config> {
	duration: Option<T::BlockNumber>,
	reward: Option<T::Balance>,
	weights: BoundedBTreeMap<T::GroupId, T::Weight, T::MaxChangesPerEpoch>,
}

pub type DomainIdOf<T> = <<T as Config>::Domain as TypedGet>::Type;

#[frame_support::pallet]
pub mod pallet {
	use super::*;

	#[pallet::config]
	pub trait Config: frame_system::Config {
		type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

		/// Required origin for admin purposes for configuring groups and currencies.
		type AdminOrigin: EnsureOrigin<Self::RuntimeOrigin>;

		/// Type used to handle balances.
		type Balance: Balance + MaxEncodedLen + FixedPointOperand;

		/// Domain identification used by this pallet
		type Domain: TypedGet;

		/// Type used to identify currencies.
		type CurrencyId: AssetId + MaxEncodedLen + Clone + Ord;

		/// Type used to identify groups.
		type GroupId: Parameter + MaxEncodedLen + Ord + Copy;

		/// Type used to handle group weights.
		type Weight: Parameter + MaxEncodedLen + EnsureAdd + Unsigned + FixedPointOperand + Default;

		/// The reward system used.
		type Rewards: GroupRewards<Balance = Self::Balance, GroupId = Self::GroupId>
			+ AccountRewards<
				Self::AccountId,
				Balance = Self::Balance,
				CurrencyId = (DomainIdOf<Self>, Self::CurrencyId),
			> + CurrencyGroupChange<
				GroupId = Self::GroupId,
				CurrencyId = (DomainIdOf<Self>, Self::CurrencyId),
			> + DistributedRewards<Balance = Self::Balance, GroupId = Self::GroupId>;

		/// Max groups used by this pallet.
		/// If this limit is reached, the exceeded groups are either not computed and not stored.
		#[pallet::constant]
		type MaxGroups: Get<u32> + TypeInfo;

		/// Max number of changes of the same type enqueued to apply in the next epoch.
		/// Max calls to [`Pallet::set_group_weight()`] or to [`Pallet::set_currency_group()`] with
		/// the same id.
		#[pallet::constant]
		type MaxChangesPerEpoch: Get<u32> + TypeInfo + sp_std::fmt::Debug + Clone + PartialEq;

		/// Initial epoch duration.
		/// This value can be updated later using [`Pallet::set_epoch_duration()`]`.
		#[pallet::constant]
		type InitialEpochDuration: Get<Self::BlockNumber>;

		#[pallet::constant]
		type CollatorCurrencyId: Get<Self::CurrencyId> + TypeInfo;

		#[pallet::constant]
		type CollatorGroupId: Get<Self::GroupId> + TypeInfo;

		#[pallet::constant]
		type DefaultCollatorStake: Get<Self::Balance> + TypeInfo;

		/// Information of runtime weights
		type WeightInfo: WeightInfo;
	}

	#[pallet::pallet]
	#[pallet::generate_store(pub(super) trait Store)]
	pub struct Pallet<T>(_);

	/// Contains the timestamp in blocks when the current epoch is finalized.
	//
	// Although this value could be stored inside `EpochData`,
	// we maintain it separately to avoid deserializing the whole EpochData struct each `on_initialize()` call.
	// EpochData could be relatively big if there many groups.
	// We dont have to deserialize the whole struct 99% of the time (assuming a duration of 100 blocks),
	// we only need to perform that action when the epoch finalized, 1% of the time.
	#[pallet::storage]
	pub(super) type EndOfEpoch<T: Config> = StorageValue<_, T::BlockNumber, ValueQuery>;

	/// Data associated to the current epoch.
	#[pallet::storage]
	pub(super) type ActiveEpochData<T: Config> = StorageValue<_, EpochData<T>, ValueQuery>;

	/// Pending update data used when the current epoch finalizes.
	/// Once it's used for the update, it's reset.
	#[pallet::storage]
	pub(super) type NextEpochChanges<T: Config> = StorageValue<_, EpochChanges<T>, ValueQuery>;

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		NewEpoch {
			ends_on: T::BlockNumber,
			reward: T::Balance,
			last_changes: EpochChanges<T>,
		},
	}

	#[pallet::error]
	pub enum Error<T> {
		/// Limit of max calls with same id to [`Pallet::set_group_weight()`] or
		/// [`Pallet::set_currency_group()`] reached.
		MaxChangesPerEpochReached,
	}

	#[pallet::hooks]
	impl<T: Config> Hooks<T::BlockNumber> for Pallet<T> {
		fn on_initialize(current_block: T::BlockNumber) -> Weight {
			let ends_on = EndOfEpoch::<T>::get();

			if ends_on > current_block {
				return T::DbWeight::get().reads(1);
			}

			let mut groups = 0;
			let mut weight_changes = 0;

			transactional::with_storage_layer(|| -> DispatchResult {
				NextEpochChanges::<T>::try_mutate(|changes| -> DispatchResult {
					ActiveEpochData::<T>::try_mutate(|epoch_data| {
						groups = T::Rewards::distribute_reward_with_weights(
							epoch_data.reward,
							epoch_data.weights.iter().map(|(g, w)| (*g, *w)),
						)
						.map(|results| results.len() as u32)?;

						for (&group_id, &weight) in &changes.weights {
							epoch_data.weights.try_insert(group_id, weight).ok();
							weight_changes += 1;
						}

						epoch_data.reward = changes.reward.unwrap_or(epoch_data.reward);
						epoch_data.duration = changes.duration.unwrap_or(epoch_data.duration);

						let ends_on = ends_on.max(current_block).ensure_add(epoch_data.duration)?;

						EndOfEpoch::<T>::set(ends_on);

						Self::deposit_event(Event::NewEpoch {
							ends_on: ends_on,
							reward: epoch_data.reward,
							last_changes: mem::take(changes),
						});

						Ok(())
					})
				})
			})
			.ok();

			T::WeightInfo::on_initialize(groups, weight_changes)
		}
	}

	// TODO: Handle group total stake reduction when single collator is changed
	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// Admin method to deposit a stake amount associated to a currency for the target account.
		/// The account must have enough currency to make the deposit,
		/// if not, an Err will be returned.
		#[pallet::weight(T::WeightInfo::stake())]
		#[transactional]
		pub fn stake(
			origin: OriginFor<T>,
			currency_id: T::CurrencyId,
			account_id: T::AccountId,
			amount: T::Balance,
		) -> DispatchResult {
			T::AdminOrigin::ensure_origin(origin)?;

			T::Rewards::deposit_stake((T::Domain::get(), currency_id), &account_id, amount)
		}

		/// Admin method to reduce the stake amount associated to a currency for the target account.
		/// The account must have enough currency staked to make the withdraw,
		/// if not, an Err will be returned.
		#[pallet::weight(T::WeightInfo::unstake())]
		#[transactional]
		pub fn unstake(
			origin: OriginFor<T>,
			currency_id: T::CurrencyId,
			account_id: T::AccountId,
			amount: T::Balance,
		) -> DispatchResult {
			T::AdminOrigin::ensure_origin(origin)?;

			T::Rewards::withdraw_stake((T::Domain::get(), currency_id), &account_id, amount)
		}

		/// Claims the reward the associated to a currency.
		/// The reward will be transferred to the target account.
		#[pallet::weight(T::WeightInfo::claim_reward())]
		#[transactional]
		pub fn claim_reward(
			origin: OriginFor<T>,
			currency_id: T::CurrencyId,
			account_id: T::AccountId,
		) -> DispatchResult {
			ensure_signed(origin)?;

			T::Rewards::claim_reward((T::Domain::get(), currency_id), &account_id).map(|_| ())
		}

		/// Admin method to set the reward amount used for the next epochs.
		/// Current epoch is not affected by this call.
		#[pallet::weight(T::WeightInfo::set_distributed_reward())]
		pub fn set_distributed_reward(origin: OriginFor<T>, balance: T::Balance) -> DispatchResult {
			T::AdminOrigin::ensure_origin(origin)?;

			NextEpochChanges::<T>::mutate(|changes| changes.reward = Some(balance));

			Ok(())
		}

		/// Admin method to set the duration used for the next epochs.
		/// Current epoch is not affected by this call.
		#[pallet::weight(T::WeightInfo::set_epoch_duration())]
		pub fn set_epoch_duration(origin: OriginFor<T>, blocks: T::BlockNumber) -> DispatchResult {
			T::AdminOrigin::ensure_origin(origin)?;

			NextEpochChanges::<T>::mutate(|changes| changes.duration = Some(blocks));

			Ok(())
		}

		/// Admin method to set the group weights used for the next epochs.
		/// Current epoch is not affected by this call.
		#[pallet::weight(T::WeightInfo::set_group_weight())]
		pub fn set_group_weight(
			origin: OriginFor<T>,
			group_id: T::GroupId,
			weight: T::Weight,
		) -> DispatchResult {
			T::AdminOrigin::ensure_origin(origin)?;

			NextEpochChanges::<T>::try_mutate(|changes| {
				changes
					.weights
					.try_insert(group_id, weight)
					.map_err(|_| Error::<T>::MaxChangesPerEpochReached)
			})?;

			Ok(())
		}
	}
}

/// Extension to an existing `SessionManager` `I` which sets the collators for the next session.
/// Executes the underlying `I::new_session` and adjusts stake for new and leaving collators inherently.
struct SessionManager<T, S, I>(
	sp_std::marker::PhantomData<T>,
	sp_std::marker::PhantomData<S>,
	sp_std::marker::PhantomData<I>,
);

impl<T, S, I, ValidatorId> pallet_session::SessionManager<ValidatorId> for SessionManager<T, S, I>
where
	T: Config,
	S: pallet_session::Config,
	I: pallet_session::SessionManager<ValidatorId>,
	ValidatorId: Into<T::AccountId> + PartialEq<<S as pallet_session::Config>::ValidatorId> + Clone,
	<S as pallet_session::Config>::ValidatorId: Into<T::AccountId> + PartialEq<ValidatorId>,
{
	// TODO: Maybe we want to wrap potential failures into transactional::with_storage_layer?
	// TODO: Benchmark
	fn new_session(index: sp_staking::SessionIndex) -> Option<Vec<ValidatorId>> {
		// Get upcoming validators from original SessionManager
		// NOTE: This call registers its own extra unchecked weight
		let maybe_next_validators = I::new_session(index);

		let current_validators = Validators::<S>::get();
		let mut weight = T::DbWeight::get().reads(1);

		// TODO: Try to get rid of as much cloning as possible
		maybe_next_validators.clone().map(|next_validators| {
			// Stake for new collators
			next_validators
				.clone()
				.into_iter()
				.filter(|next| !current_validators.iter().any(|current| next == current))
				.for_each(|new| {
					// Must not fail
					let _ = T::Rewards::deposit_stake(
						(T::Domain::get(), T::CollatorCurrencyId::get()),
						&new.into(),
						T::DefaultCollatorStake::get(),
					)
					.map_err(|_e| {
						// Should never happen
						log::error!(target: "runtime::block_rewards", "Staking for new collator failed");
					});
					// TODO: For now, add more than used (we don't need to validate signature)
					weight.saturating_accrue(T::WeightInfo::stake());
				});

			// Unstake for leaving collators
			current_validators
				.into_iter()
				.filter(|next| !next_validators.iter().any(|current| next == current))
				.for_each(|leaving| {
					let amount = T::Rewards::account_stake(
						(T::Domain::get(), T::CollatorCurrencyId::get()),
						&leaving.clone().into(),
					);
					weight.saturating_accrue(T::DbWeight::get().reads(1));

					// Must not fail
					let _ = T::Rewards::withdraw_stake(
						(T::Domain::get(), T::CollatorCurrencyId::get()),
						&leaving.into(),
						amount,
					)
					.map_err(|_e| {
						// Should never happen
						log::error!(target: "runtime::block_rewards", "Unstaking for leaving collator failed");
					});
					// TODO: For now, add more than used (we don't need to validate signature)
					weight.saturating_accrue(T::WeightInfo::unstake());
				});
		});

		frame_system::Pallet::<T>::register_extra_weight_unchecked(
			// T::WeightInfo::new_session(candidates_len_before as u32, removed as u32),
			weight,
			DispatchClass::Mandatory,
		);

		maybe_next_validators
	}

	fn start_session(_: sp_staking::SessionIndex) {
		// we don't care.
	}

	fn end_session(_: sp_staking::SessionIndex) {
		// we don't care.
	}
}
