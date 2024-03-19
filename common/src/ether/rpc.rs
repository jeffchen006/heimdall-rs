use crate::{debug_max, error::Error, utils::io::logging::Logger};
use async_openai::Client;
use backoff::{ExponentialBackoff};
use ethers::{
    addressbook::contract, core::types::Address, etherscan::contract, providers::{Http, Middleware, Provider}, types::{
        BlockId, BlockNumber, BlockTrace, Filter, FilterBlockOption, StateDiff, TraceType, Transaction, H256
    }
};
// use ethers::core::abi::Abi;
use ethabi::Contract;
use ethabi::Function;
use ethers::types::{Chain};
use ethers::prelude;

use heimdall_cache::{read_cache, store_cache};
use tokio::fs::read;
use std::{clone, collections::BTreeMap, str::FromStr, time::Duration};
use std::env::set_var;


/// Get the chainId of the provided RPC URL
///
/// ```no_run
/// use heimdall_common::ether::rpc::chain_id;
///
/// // let chain_id = chain_id("https://eth.llamarpc.com").await?;
/// //assert_eq!(chain_id, 1);
/// ```
pub async fn chain_id(rpc_url: &str) -> Result<u64, Error> {
    backoff::future::retry(
        ExponentialBackoff {
            max_elapsed_time: Some(Duration::from_secs(10)),
            ..ExponentialBackoff::default()
        },
    || async {
        // get a new logger
        let logger = Logger::default();

        debug_max!(&format!("checking chain id for rpc url: '{}'", &rpc_url));

        // check the cache for a matching rpc url
        let cache_key = format!("chain_id.{}", &rpc_url.replace('/', "").replace(['.', ':'], "-"));
        if let Some(chain_id) = read_cache(&cache_key)
            .map_err(|_| logger.error(&format!("failed to read cache for rpc url: {:?}", &rpc_url)))?
        {
            logger.debug(&format!("found cached chain id for rpc url: {:?}", &rpc_url));
            return Ok(chain_id)
        }

        // make sure the RPC provider isn't empty
        if rpc_url.is_empty() {
            logger.error("reading on-chain data requires an RPC provider. Use `heimdall --help` for more information.");
            return Err(backoff::Error::Permanent(()))
        }

        // create new provider
        let provider = match Provider::<Http>::try_from(rpc_url) {
            Ok(provider) => provider,
            Err(_) => {
                logger.error(&format!("failed to connect to RPC provider '{}' .", &rpc_url));
                return Err(backoff::Error::Permanent(()))
            }
        };

        // fetch the chain id from the node
        let chain_id = match provider.get_chainid().await {
            Ok(chain_id) => chain_id,
            Err(_) => {
                logger.error(&format!("failed to fetch chain id from '{}' .", &rpc_url));
                return Err(backoff::Error::Transient { err: (), retry_after: None })
            }
        };

        // cache the results
        store_cache(&cache_key, chain_id.as_u64(), None)
            .map_err(|_| logger.error(&format!("failed to cache chain id for rpc url: {:?}", &rpc_url)))?;

        debug_max!(&format!("chain_id is '{}'", &chain_id));

        Ok(chain_id.as_u64())
    })
    .await
    .map_err(|e| Error::Generic(format!("failed to get chain id: {:?}", e)))
}

/// Get the bytecode of the provided contract address
///
/// ```no_run
/// use heimdall_common::ether::rpc::get_code;
///
/// // let bytecode = get_code("0x0", "https://eth.llamarpc.com").await;
/// // assert!(bytecode.is_ok());
/// ```
pub async fn get_code(contract_address: &str, rpc_url: &str) -> Result<String, Error> {
    backoff::future::retry(
        ExponentialBackoff {
            max_elapsed_time: Some(Duration::from_secs(10)),
            ..ExponentialBackoff::default()
        },
    || async {
        // get a new logger
        let logger = Logger::default();

        // get chain_id
        let chain_id = chain_id(rpc_url).await.unwrap_or(1);

        // check the cache for a matching address
        if let Some(bytecode) = read_cache(&format!("contract.{}.{}", &chain_id, &contract_address))
            .map_err(|_| logger.error(&format!("failed to read cache for contract: {:?}", &contract_address)))?
        {
            logger.debug(&format!("found cached bytecode for '{}' .", &contract_address));
            return Ok(bytecode)
        }

        debug_max!("fetching bytecode from node for contract: '{}' .", &contract_address);

        // make sure the RPC provider isn't empty
        if rpc_url.is_empty() {
            logger.error("reading on-chain data requires an RPC provider. Use `heimdall --help` for more information.");
            return Err(backoff::Error::Permanent(()))
        }

        // create new provider
        let provider = match Provider::<Http>::try_from(rpc_url) {
            Ok(provider) => provider,
            Err(_) => {
                logger.error(&format!("failed to connect to RPC provider '{}' .", &rpc_url));
                return Err(backoff::Error::Permanent(()))
            }
        };

        // safely unwrap the address
        let address = match contract_address.parse::<Address>() {
            Ok(address) => address,
            Err(_) => {
                logger.error(&format!("failed to parse address '{}' .", &contract_address));
                return Err(backoff::Error::Permanent(()))
            }
        };

        // fetch the bytecode at the address
        let bytecode_as_bytes = match provider.get_code(address, None).await {
            Ok(bytecode) => bytecode,
            Err(_) => {
                logger.error(&format!("failed to fetch bytecode from '{}' .", &contract_address));
                return Err(backoff::Error::Transient { err: (), retry_after: None })
            }
        };

        // cache the results
        store_cache(
            &format!("contract.{}.{}", &chain_id, &contract_address),
            bytecode_as_bytes.to_string().replacen("0x", "", 1),
            None,
        )
        .map_err(|_| logger.error(&format!("failed to cache bytecode for contract: {:?}", &contract_address)))?;

        Ok(bytecode_as_bytes.to_string().replacen("0x", "", 1))
    })
    .await
    .map_err(|_| Error::Generic(format!("failed to get bytecode for contract: {:?}", &contract_address)))
}

/// Get the raw transaction data of the provided transaction hash
///
/// ```no_run
/// use heimdall_common::ether::rpc::get_code;
///
/// // let bytecode = get_code("0x0", "https://eth.llamarpc.com").await;
/// // assert!(bytecode.is_ok());
/// ```
/// TODO: check for caching
pub async fn get_transaction(transaction_hash: &str, rpc_url: &str) -> Result<Transaction, Error> {
    backoff::future::retry(
        ExponentialBackoff {
            max_elapsed_time: Some(Duration::from_secs(10)),
            ..ExponentialBackoff::default()
        },
    || async {
        // get a new logger
        let logger = Logger::default();

        debug_max!(&format!(
            "fetching calldata from node for transaction: '{}' .",
            &transaction_hash
        ));

        // make sure the RPC provider isn't empty
        if rpc_url.is_empty() {
            logger.error("reading on-chain data requires an RPC provider. Use `heimdall --help` for more information.");
            return Err(backoff::Error::Permanent(()));
        }

        // create new provider
        let provider = match Provider::<Http>::try_from(rpc_url) {
            Ok(provider) => provider,
            Err(_) => {
                logger.error(&format!("failed to connect to RPC provider '{}' .", &rpc_url));
                return Err(backoff::Error::Permanent(()))
            }
        };

        // safely unwrap the transaction hash
        let transaction_hash_hex = match H256::from_str(transaction_hash) {
            Ok(transaction_hash) => transaction_hash,
            Err(_) => {
                logger.error(&format!("failed to parse transaction hash '{}' .", &transaction_hash));
                return Err(backoff::Error::Permanent(()))
            }
        };

        // get the transaction
        let tx = match provider.get_transaction(transaction_hash_hex).await {
            Ok(tx) => match tx {
                Some(tx) => tx,
                None => {
                    logger.error(&format!("transaction '{}' doesn't exist.", &transaction_hash));
                    return Err(backoff::Error::Permanent(()))
                }
            },
            Err(_) => {
                logger.error(&format!("failed to fetch calldata from '{}' .", &transaction_hash));
                return Err(backoff::Error::Transient { err: (), retry_after: None })
            }
        };

        Ok(tx)
    })
    .await
    .map_err(|_| Error::Generic(format!("failed to get transaction: {:?}", &transaction_hash)))
}

/// Get the storage diff of the provided transaction hash
///
/// ```no_run
/// use heimdall_common::ether::rpc::get_storage_diff;
///
/// // let storage_diff = get_storage_diff("0x0", "https://eth.llamarpc.com").await;
/// // assert!(storage_diff.is_ok());
/// ```
pub async fn get_storage_diff(
    transaction_hash: &str,
    rpc_url: &str,
) -> Result<Option<StateDiff>, Error> {
    backoff::future::retry(
        ExponentialBackoff {
            max_elapsed_time: Some(Duration::from_secs(10)),
            ..ExponentialBackoff::default()
        },
        || async {
            // create new logger
            let logger = Logger::default();

            // get chain_id
            let chain_id = chain_id(rpc_url).await
                .map_err(|_| logger.error(&format!("failed to get chain id for rpc url: {:?}", &rpc_url)))?;

            // check the cache for a matching address
            if let Some(state_diff) =
                read_cache(&format!("diff.{}.{}", &chain_id, &transaction_hash))
                .map_err(|_| logger.error(&format!("failed to read cache for transaction: {:?}", &transaction_hash)))?
            {
                debug_max!("found cached state diff for transaction '{}' .", &transaction_hash);
                return Ok(state_diff)
            }

            debug_max!(&format!(
                "fetching storage diff from node for transaction: '{}' .",
                &transaction_hash
            ));

            // create new provider
            let provider = match Provider::<Http>::try_from(rpc_url) {
                Ok(provider) => provider,
                Err(_) => {
                    logger.error(&format!("failed to connect to RPC provider '{}' .", &rpc_url));
                    return Err(backoff::Error::Permanent(()))
                }
            };

            // safely unwrap the transaction hash
            let transaction_hash_hex = match H256::from_str(transaction_hash) {
                Ok(transaction_hash) => transaction_hash,
                Err(_) => {
                    logger.error(&format!(
                        "failed to parse transaction hash '{}' .",
                        &transaction_hash
                    ));
                    return Err(backoff::Error::Permanent(()))
                }
            };

            // fetch the state diff for the transaction
            let state_diff = match provider
                .trace_replay_transaction(transaction_hash_hex, vec![TraceType::StateDiff])
                .await {
                Ok(traces) => traces.state_diff,
                Err(_) => {
                    logger.error(&format!(
                        "failed to replay and trace transaction '{}' . does your RPC provider support it?",
                        &transaction_hash
                    ));
                    return Err(backoff::Error::Transient { err: (), retry_after: None })
                }
            };

            // write the state diff to the cache
            store_cache(
                &format!("diff.{}.{}", &chain_id, &transaction_hash),
                &state_diff,
                None,
            )
            .map_err(|_| {
                logger.error(&format!(
                    "failed to cache state diff for transaction: {:?}",
                    &transaction_hash
                ))
            })?;

            debug_max!("fetched state diff for transaction '{}' .", &transaction_hash);

            Ok(state_diff)
        },
    )
    .await
    .map_err(|_| Error::Generic(format!("failed to get storage diff for transaction: {:?}", &transaction_hash)))
}

/// Get the raw trace data of the provided transaction hash
///
/// ```no_run
/// use heimdall_common::ether::rpc::get_trace;
///
/// // let trace = get_trace("0x0", "https://eth.llamarpc.com").await;
/// // assert!(trace.is_ok());
/// ```
/// TODO: check for caching
pub async fn get_trace(transaction_hash: &str, rpc_url: &str) -> Result<BlockTrace, Error> {
    backoff::future::retry(
        ExponentialBackoff {
            max_elapsed_time: Some(Duration::from_secs(10)),
            ..ExponentialBackoff::default()
        },
        || async {
            // create new logger
            let logger = Logger::default();

            debug_max!(&format!(
                "fetching trace from node for transaction: '{}' .",
                &transaction_hash
            ));

            // create new provider
            let provider = match Provider::<Http>::try_from(rpc_url) {
                Ok(provider) => provider,
                Err(_) => {
                    logger.error(&format!("failed to connect to RPC provider '{}' .", &rpc_url));
                    return Err(backoff::Error::Permanent(()))
                }
            };

            // safely unwrap the transaction hash
            let transaction_hash_hex = match H256::from_str(transaction_hash) {
                Ok(transaction_hash) => transaction_hash,
                Err(_) => {
                    logger.error(&format!(
                        "failed to parse transaction hash '{}' .",
                        &transaction_hash
                    ));
                    return Err(backoff::Error::Permanent(()))
                }
            };

            // fetch the trace for the transaction
            let block_trace = match provider
                .trace_replay_transaction(
                    transaction_hash_hex,
                    vec![TraceType::StateDiff, TraceType::VmTrace, TraceType::Trace],
                )
                .await
            {
                Ok(traces) => traces,
                Err(e) => {
                    logger.error(&format!(
                        "failed to replay and trace transaction '{}' . does your RPC provider support it?",
                        &transaction_hash
                    ));
                    logger.error(&format!("error: '{e}' ."));
                    return Err(backoff::Error::Transient { err: (), retry_after: None })
                }
            };

            debug_max!("fetched trace for transaction '{}' .", &transaction_hash);

            Ok(block_trace)
        },
    )
    .await
    .map_err(|_| Error::Generic(format!("failed to get trace for transaction: {:?}", &transaction_hash)))
}

/// Get all logs for the given block number
///
/// ```no_run
/// use heimdall_common::ether::rpc::get_block_logs;
///
/// // let logs = get_block_logs(1, "https://eth.llamarpc.com").await;
/// // assert!(logs.is_ok());
/// ```
pub async fn get_block_logs(
    block_number: u64,
    rpc_url: &str,
) -> Result<Vec<ethers::core::types::Log>, Error> {
    backoff::future::retry(
        ExponentialBackoff {
            max_elapsed_time: Some(Duration::from_secs(10)),
            ..ExponentialBackoff::default()
        },
        || async {
            // create new logger
            let logger = Logger::default();

            debug_max!(&format!("fetching logs from node for block: '{}' .", &block_number));

            // create new provider
            let provider = match Provider::<Http>::try_from(rpc_url) {
                Ok(provider) => provider,
                Err(_) => {
                    logger.error(&format!("failed to connect to RPC provider '{}' .", &rpc_url));
                    return Err(backoff::Error::Permanent(()));
                }
            };

            // fetch the logs for the block
            let logs = match provider
                .get_logs(&Filter {
                    block_option: FilterBlockOption::Range {
                        from_block: Some(BlockNumber::from(block_number)),
                        to_block: Some(BlockNumber::from(block_number)),
                    },
                    address: None,
                    topics: [None, None, None, None],
                })
                .await
            {
                Ok(logs) => logs,
                Err(_) => {
                    logger.error(&format!(
                        "failed to fetch logs for block '{}' . does your RPC provider support it?",
                        &block_number
                    ));
                    return Err(backoff::Error::Transient { err: (), retry_after: None });
                }
            };

            debug_max!("fetched logs for block '{}' .", &block_number);

            Ok(logs)
        },
    )
    .await
    .map_err(|_| Error::Generic(format!("failed to get logs for block: {:?}", &block_number)))
}



/// Get the storage of the provided storage slot and contract address
/// 
/// 
pub async fn get_storage_at(
    block_number: u64,
    contract_address: &str,
    storage_slot: H256,
    rpc_url: &str,
) -> Result<H256, Error> {
    backoff::future::retry(
        ExponentialBackoff {
            max_elapsed_time: Some(Duration::from_secs(10)),
            ..ExponentialBackoff::default()
        },
    || async {
        // get a new logger
        let logger = Logger::default();

        // get chain_id
        let chain_id = chain_id(rpc_url).await.unwrap_or(1);

        // check the cache for a matching address
        if let Some(storage) = read_cache(&format!("storage.{}.{}.{}.{}", &chain_id, &block_number, &contract_address, &storage_slot))
            .map_err(|_| logger.error(&format!("failed to read cache for storage: {}.{} at block {}", &contract_address, &storage_slot, &block_number)))?
        {
            logger.debug(&format!("found cached storage for '{}.{}' at block {}.", &contract_address, &storage_slot, &block_number));
            return Ok(storage)
        }

        debug_max!("fetching storage from node for storage slot: '{}.{}' .", &contract_address, &storage_slot);

        // make sure the RPC provider isn't empty
        if rpc_url.is_empty() {
            logger.error("reading on-chain data requires an RPC provider. Use `heimdall --help` for more information.");
            return Err(backoff::Error::Permanent(()))
        }

        // create new provider
        let provider = match Provider::<Http>::try_from(rpc_url) {
            Ok(provider) => provider,
            Err(_) => {
                logger.error(&format!("failed to connect to RPC provider '{}' .", &rpc_url));
                return Err(backoff::Error::Permanent(()))
            }
        };

        // safely unwrap the address
        let address = match contract_address.parse::<Address>() {
            Ok(address) => address,
            Err(_) => {
                logger.error(&format!("failed to parse address '{}' .", &contract_address));
                return Err(backoff::Error::Permanent(()))
            }
        };

        // fetch the storage at the address
        let storage = match provider.get_storage_at(address, storage_slot, Some(BlockId::from(block_number))).await {
            Ok(storage) => storage,
            Err(_) => {
                logger.error(&format!("failed to fetch storage from '{}' .", &contract_address));
                return Err(backoff::Error::Transient { err: (), retry_after: None })
            }
        };

        // cache the results
        store_cache(
            &format!("storage.{}.{}.{}.{}", &chain_id, &block_number, &contract_address, &storage_slot),
            storage,
            None,
        )
        .map_err(|_| logger.error(&format!("failed to cache storage for contract: {:?}", &contract_address)))?;
        
        Ok(storage)
    })
    .await
    .map_err(|_| Error::Generic(format!("failed to get storage for contract: {:?}", &contract_address)))
}


pub async fn get_functions_from_contract(contract_address: &str) -> Result<BTreeMap<String, Function>, Error> {
    let contract_info = get_contract_info(contract_address).await;
    // one function name could have different functions with different input params
    // but one function selector could only have one function
    match contract_info {
        Ok(contract_info) => {
            let mut selector_tree = BTreeMap::new();
            let functions_tree = contract_info.functions;
            for (_, functions) in functions_tree.iter() {
                for function in functions {
                    let short_signature = function.short_signature();
                    // covert it to a hex string, like 0xb214faa6
                    let mut hex_string = String::new();
                    for byte in short_signature.iter() {
                        hex_string.push_str(&format!("{:02x}", byte));
                    }
                    selector_tree.insert(hex_string, function.clone());
                }
            }
            Ok(selector_tree)
        },
        Err(e) => {
            return Err(e)
        }
    }
}


pub async fn get_contract_info(contract_address: &str) -> Result<Contract, Error> {
    // get a new logger
    let logger = Logger::default();
    // get chain_id
    let chain_id: u64 = 1;
    // check the cache for a matching address
    let kkkkk: Result<Option<String>, heimdall_cache::error::Error> = read_cache(&format!("contract_info.{}.{}", &chain_id, &contract_address));
    match kkkkk {
        Ok(some_serialized_contract) => {
            if some_serialized_contract == None {
                // means it was not cached
                // logger.error(&format!("failed to read cache for contract_info: {:?}", &contract_address));
            } else {
                let serialized_contract: String = some_serialized_contract.unwrap(); // Explicit type annotation
                let contract: Contract = serde_json::from_str(&serialized_contract).unwrap();
                return Ok(contract)
            }
        },
        Err(_) => {
            logger.error(&format!("failed to read cache for contract_info: {:?}", &contract_address));
        }
    }
    let address_h160 = contract_address.parse().unwrap();
    let client = prelude::Client::new_from_env(Chain::Mainnet).unwrap();
    let contract_info = match client.contract_abi(address_h160).await {
        Ok(contract_info) => contract_info,
        Err(_) => {
            // logger.error(&format!("failed to fetch contract info from '{}' .", &contract_address));
            return Err(Error::Generic(format!("failed to get contract info for contract: {:?}", &contract_address)))
        }
    };

    // serialize the contract
    let serialized_contract = serde_json::to_string(&contract_info).unwrap();
    let asassaas: Contract = serde_json::from_str(&serialized_contract).unwrap();
    println!("asassaas: {:?}", asassaas);
    // cache the results
    let _ = store_cache(
        &format!("contract_info.{}.{}", &chain_id, &contract_address),
        serialized_contract,
        None,
    )
    .map_err(|_| logger.error(&format!("failed to cache contract info for contract: {:?}", &contract_address)));
    Ok(contract_info)
}






// TODO: add tests
#[cfg(test)]
pub mod tests {
    use crate::{ether::rpc::*, utils::hex::ToLowerHex};

    #[tokio::test]
    async fn test_chain_id() {
        let rpc_url = "https://eth.llamarpc.com";
        let rpc_chain_id = chain_id(rpc_url).await.expect("chain_id() returned an error!");

        assert_eq!(rpc_chain_id, 1);
    }

    #[tokio::test]
    async fn test_chain_id_invalid_rpc_url() {
        let rpc_url = "https://none.llamarpc.com";
        let rpc_chain_id = chain_id(rpc_url).await;

        assert!(rpc_chain_id.is_err())
    }

    #[tokio::test]
    async fn test_get_code() {
        let contract_address = "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2";
        let rpc_url = "https://eth.llamarpc.com";
        let bytecode =
            get_code(contract_address, rpc_url).await.expect("get_code() returned an error!");

        assert!(!bytecode.is_empty());
    }

    #[tokio::test]
    async fn test_get_code_invalid_contract_address() {
        let contract_address = "0x0";
        let rpc_url = "https://eth.llamarpc.com";
        let bytecode = get_code(contract_address, rpc_url).await;

        assert!(bytecode.is_err())
    }

    #[tokio::test]
    async fn test_get_transaction() {
        let transaction_hash = "0x9a5f4ef7678a94dd87048eeec931d30af21b1f4cecbf7e850a531d2bb64a54ac";
        let rpc_url = "https://eth.llamarpc.com";
        let transaction = get_transaction(transaction_hash, rpc_url)
            .await
            .expect("get_transaction() returned an error!");

        assert_eq!(transaction.hash.to_lower_hex(), transaction_hash);
    }

    #[tokio::test]
    async fn test_get_transaction_invalid_transaction_hash() {
        let transaction_hash = "0x0";
        let rpc_url = "https://eth.llamarpc.com";
        let transaction = get_transaction(transaction_hash, rpc_url).await;

        assert!(transaction.is_err())
    }

    #[tokio::test]
    async fn test_get_storage_diff() {
        let transaction_hash = "0x9a5f4ef7678a94dd87048eeec931d30af21b1f4cecbf7e850a531d2bb64a54ac";
        let rpc_url = "https://eth.llamarpc.com";
        let storage_diff = get_storage_diff(transaction_hash, rpc_url)
            .await
            .expect("get_storage_diff() returned an error!");

        assert!(storage_diff.is_some());
    }

    #[tokio::test]
    async fn test_get_storage_diff_invalid_transaction_hash() {
        let transaction_hash = "0x0";
        let rpc_url = "https://eth.llamarpc.com";
        let storage_diff = get_storage_diff(transaction_hash, rpc_url).await;

        assert!(storage_diff.is_err())
    }

    #[tokio::test]
    async fn test_get_trace() {
        let transaction_hash = "0x9a5f4ef7678a94dd87048eeec931d30af21b1f4cecbf7e850a531d2bb64a54ac";
        let rpc_url = "https://eth.llamarpc.com";
        let trace = get_trace(transaction_hash, rpc_url).await;

        assert!(trace.is_ok())
    }

    #[tokio::test]
    async fn test_get_trace_invalid_transaction_hash() {
        let transaction_hash = "0x0";
        let rpc_url = "https://eth.llamarpc.com";
        let trace = get_trace(transaction_hash, rpc_url).await;

        assert!(trace.is_err())
    }

    #[tokio::test]
    async fn test_get_block_logs() {
        let block_number = 18_000_000;
        let rpc_url = "https://eth.llamarpc.com";
        let logs = get_block_logs(block_number, rpc_url)
            .await
            .expect("get_block_logs() returned an error!");

        assert!(!logs.is_empty());
    }

    #[tokio::test]
    async fn test_get_storage_at() {
        let block_number = 19_446_800;
        let contract_address = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"; // USDC
        let storage_slot = H256::from_str("0x0000000000000000000000000000000000000000000000000000000000000000").unwrap();
        let rpc_url = "https://eth.llamarpc.com";
        let storage = get_storage_at(block_number, contract_address, storage_slot, rpc_url)
            .await
            .expect("get_storage_at() returned an error!");

        println!("storage: {:?}", storage);

        assert!(storage == H256::from_str("0x000000000000000000000000fcb19e6a322b27c06842a71e8c725399f049ae3a").unwrap());
    }

    #[tokio::test]
    async fn test_get_contract() {
        set_var("ETHERSCAN_API_KEY", "I7R59ER7AQ8HEBYTNR15ETXJSMTD86BHA4");
        // USDC
        let contract_address = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48";
        let contract = get_contract_info(contract_address).await.unwrap();
        println!("contract.functions:\n {:?}", contract.functions);
        assert!(contract.functions.len() > 0);

        for (name, functions) in contract.functions.iter() {
            println!("name: {:?}", name);
            for function in functions {
                println!("short_signature: {:?}", function.short_signature());
                let short_signature = function.short_signature();
                // covert it to a hex string, like 0xb214faa6
                let mut hex_string = String::new();
                for byte in short_signature.iter() {
                    hex_string.push_str(&format!("{:02x}", byte));
                }
                println!("hex_string: {:?}", hex_string);
                println!("function: {:?}", function.signature());
            }
        }
    }

    #[tokio::test]
    async fn test_get_functions_from_contract() {
        set_var("ETHERSCAN_API_KEY", "I7R59ER7AQ8HEBYTNR15ETXJSMTD86BHA4");
        // USDC
        let contract_address = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48";
        let functions = get_functions_from_contract(contract_address).await.unwrap();
        println!("functions: {:?}", functions);
        assert!(functions.len() > 0);
    }

    #[tokio::test]
    async fn test_get_contract_close_source() {
        set_var("ETHERSCAN_API_KEY", "I7R59ER7AQ8HEBYTNR15ETXJSMTD86BHA4");

        // a close source contract: 0xfca4416d9def20ac5b6da8b8b322b6559770efbf
        let contract_address = "0xfca4416d9def20ac5b6da8b8b322b6559770efbf";
        let contract = get_contract_info(contract_address).await;
        assert!(contract.is_err());

    }
}
