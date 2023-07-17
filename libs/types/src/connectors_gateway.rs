// Copyright 2023 Centrifuge Foundation (centrifuge.io).
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
use codec::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;

use crate::{domain_address::DomainAddress, EVMChainId};

#[derive(Debug, Encode, Decode, Clone, PartialEq, Eq, TypeInfo, MaxEncodedLen)]
pub struct EVMAddress {
	pub chain_id: EVMChainId,
	pub address: [u8; 20],
}

impl Into<DomainAddress> for EVMAddress {
	fn into(self) -> DomainAddress {
		DomainAddress::EVM(self.chain_id, self.address)
	}
}

impl From<EVMAddress> for EVMChainId {
	fn from(value: EVMAddress) -> Self {
		value.chain_id
	}
}
