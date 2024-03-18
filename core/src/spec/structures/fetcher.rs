/// define a structure to perform rpc requests 
/// 

use heimdall_common::{ether::{evm::core::storage, rpc::*}, utils::strings::encode_hex};
use ethers::{abi::AbiEncode, types::{H256, U256}};
use std::{process::exit, str::FromStr};


pub struct Fetcher {
    pub block_number: Option<u64>,
    pub contract_address: String,
    pub rpc_url: String,
}



impl Fetcher {
    fn is_onchain(&self) -> bool {
        self.block_number.is_some()
    }

    fn block_number(&self) -> u64 {
        self.block_number.unwrap()
    }

    pub async fn fetch_storage_slot(&self, storage_slot: U256) -> H256  {
        // force convert U256 to H256
        let storage_slot_string = storage_slot.encode_hex();
        let storage_slot_h256 = H256::from_str(&storage_slot_string).unwrap();

        let value = get_storage_at(self.block_number.unwrap(), &self.contract_address, 
        storage_slot_h256, &self.rpc_url)
            .await
            .expect("fetch_storage_slot() returned an error!");
        
        value
    } 
}



/// write some tests
#[cfg(test)]
pub mod tests {
    use super::*;

    #[tokio::test]
    async fn test_fetch_storage_slot() {
        let fetcher = Fetcher {
            block_number: Some(19_446_800),
            contract_address: "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48".to_string(),
            rpc_url: "https://eth.llamarpc.com".to_string(),
        };
        let storage_slot_string = "0x0000000000000000000000000000000000000000000000000000000000000000";
        let storage_slot_U256 = U256::from_str(storage_slot_string).unwrap();

        let storage_slot = fetcher.fetch_storage_slot(storage_slot_U256)
            .await;
        assert_eq!(storage_slot, H256::from_str("0x000000000000000000000000fcb19e6a322b27c06842a71e8c725399f049ae3a").unwrap());
    }


    #[tokio::test]
    async fn test_conversion() {
        let fetcher = Fetcher {
            block_number: Some(19_446_800),
            contract_address: "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48".to_string(),
            rpc_url: "https://eth.llamarpc.com".to_string(),
        };
        let storage_slot_string = "0x0000000000000000000000000000000000000000000000000000000000000000";
        let storage_slot_U256 = U256::from_str(storage_slot_string).unwrap();
        let storage_slot_U256_string = storage_slot_U256.encode_hex();
        // println!("storage_slot_U256_string: {}", storage_slot_U256_string);

        let storage_slot_H256 = H256::from_str(&storage_slot_U256_string).unwrap();
        // println!("storage_slot_H256: {}", storage_slot_H256);

        // H256 to U256
        let storage_slot_H256_string = storage_slot_H256.encode_hex();
        println!("storage_slot_H256_string: {}", storage_slot_H256_string);
        let storage_slot_U256 = U256::from_str(&storage_slot_H256_string).unwrap();
        println!("storage_slot_U256: {}", storage_slot_U256);




    }

}
