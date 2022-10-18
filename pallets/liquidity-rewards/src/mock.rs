use frame_support::{
	pallet_prelude::*,
	traits::{ConstU16, ConstU32, ConstU64},
	PalletId,
};
use frame_system::EnsureRoot;
#[cfg(feature = "std")]
use serde::{Deserialize, Serialize};
use sp_core::H256;
use sp_runtime::{
	testing::Header,
	traits::{BlakeTwo256, IdentityLookup},
	FixedI64,
};

use crate as pallet_liquidity_rewards;

type UncheckedExtrinsic = frame_system::mocking::MockUncheckedExtrinsic<Test>;
type Block = frame_system::mocking::MockBlock<Test>;

frame_support::construct_runtime!(
	pub enum Test where
		Block = Block,
		NodeBlock = Block,
		UncheckedExtrinsic = UncheckedExtrinsic,
	{
		System: frame_system::{Pallet, Call, Config, Storage, Event<T>},
		Tokens: orml_tokens::{Pallet, Storage, Event<T>, Config<T>},
		Rewards: pallet_rewards::{Pallet, Storage, Event<T>},
		Liquidity: pallet_liquidity_rewards::{Pallet, Storage, Event<T>},
	}
);

impl frame_system::Config for Test {
	type AccountData = ();
	type AccountId = u64;
	type BaseCallFilter = frame_support::traits::Everything;
	type BlockHashCount = ConstU64<250>;
	type BlockLength = ();
	type BlockNumber = u64;
	type BlockWeights = ();
	type Call = Call;
	type DbWeight = ();
	type Event = Event;
	type Hash = H256;
	type Hashing = BlakeTwo256;
	type Header = Header;
	type Index = u64;
	type Lookup = IdentityLookup<Self::AccountId>;
	type MaxConsumers = ConstU32<16>;
	type OnKilledAccount = ();
	type OnNewAccount = ();
	type OnSetCode = ();
	type Origin = Origin;
	type PalletInfo = PalletInfo;
	type SS58Prefix = ConstU16<42>;
	type SystemWeightInfo = ();
	type Version = ();
}

#[derive(
	Clone,
	Copy,
	PartialOrd,
	Ord,
	PartialEq,
	Eq,
	Encode,
	Decode,
	TypeInfo,
	MaxEncodedLen,
	RuntimeDebug,
)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub enum CurrencyId {
	Reward,
	A,
	B,
	C,
}

orml_traits::parameter_type_with_key! {
	pub ExistentialDeposits: |_currency_id: CurrencyId| -> u64 { 0 };
}

frame_support::parameter_types! {}

impl orml_tokens::Config for Test {
	type Amount = i64;
	type Balance = u64;
	type CurrencyId = CurrencyId;
	type DustRemovalWhitelist = frame_support::traits::Nothing;
	type Event = Event;
	type ExistentialDeposits = ExistentialDeposits;
	type MaxLocks = ();
	type MaxReserves = ();
	type OnDust = ();
	type OnKilledTokenAccount = ();
	type OnNewTokenAccount = ();
	type ReserveIdentifier = [u8; 8];
	type WeightInfo = ();
}

frame_support::parameter_types! {
	pub const RewardsPalletId: PalletId = PalletId(*b"m/reward");
	pub const RewardCurrency: CurrencyId = CurrencyId::Reward;

	#[derive(scale_info::TypeInfo)]
	pub const MaxCurrencyMovements: u32 = 3;
}

impl pallet_rewards::Config for Test {
	type Balance = u64;
	type Currency = Tokens;
	type CurrencyId = CurrencyId;
	type Event = Event;
	type GroupId = u32;
	type MaxCurrencyMovements = MaxCurrencyMovements;
	type PalletId = RewardsPalletId;
	type Rate = FixedI64;
	type RewardCurrency = RewardCurrency;
	type SignedBalance = i128;
}

impl pallet_liquidity_rewards::Config for Test {
	type AdminOrigin = EnsureRoot<u64>;
	type Balance = u64;
	type CurrencyId = CurrencyId;
	type Event = Event;
	type GroupId = u32;
	type Rewards = pallet_rewards::Pallet<Test>;
	type Weight = u32;
}

pub fn new_test_ext() -> sp_io::TestExternalities {
	let storage = frame_system::GenesisConfig::default()
		.build_storage::<Test>()
		.unwrap();

	sp_io::TestExternalities::new(storage)
}
