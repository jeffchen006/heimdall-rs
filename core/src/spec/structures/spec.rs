use std::{collections::{HashMap, HashSet}, process::exit};

use ethers::types::U256;
use heimdall_common::ether::{
    evm::core::{log::Log, opcodes::{Opcode, WrappedInput, WrappedOpcode}},
    signatures::{ResolvedError, ResolvedFunction, ResolvedLog},
};

use crate::spec::structures::fetcher::Fetcher;
use std::{str::FromStr};
use std::fmt;
use heimdall_common::ether::lexers::cleanup::Cleanup;
use async_recursion::async_recursion;


/// A spec of a contract's state at a given point in time. Will be built over the process of
/// symbolic-execution analysis.
#[derive(Clone, Debug)]
pub struct Spec {
    // META DATA:

    // the function's 4byte selector
    pub selector: String,

    // the bytecode of the contract
    pub bytecode: Vec<u8>,

    // the function's entry point in the code.
    // the entry point is the instruction the dispatcher JUMPs to when called.
    pub entry_point: u128,

    // argument structure:
    //   - key : slot operations of the argument.
    //   - value : tuple of ({slot: U256, mask: usize}, potential_types)
    pub arguments: HashMap<usize, (CalldataFrame, Vec<String>)>,

    // returns the return type for the function.
    pub returns: Option<String>,

    // modifiers
    pub pure: bool,
    pub view: bool,
    pub payable: bool,

    // stores the number of unique branches found by symbolic execution
    pub branch_count: u32,

    // 
    pub cfg_map: HashMap< (u128, u128), Vec< (u128, u128) >>,
    pub branch_specs: Vec<BranchSpec>,
    pub resolved_function: Vec<ResolvedFunction>,
}


#[derive(Clone)]
pub struct ConcolicExternallCall {
    pub call_type: String,
    pub address: WrappedOpcode,
    pub gas: WrappedOpcode,  
    pub value: Option<WrappedOpcode>, // for DelegateCall/Staticall , value is ignored
    pub extcalldata_memory: Vec<StorageFrame>,
}

impl ConcolicExternallCall {
    // to string
    pub fn to_string(&self) -> String {
        let gas = match self.gas != WrappedOpcode::new(0x5A, vec![]) {
            true => format!("gas: {}, ", self.gas.solidify().cleanup()),
            false => String::from(""),
        };
        let extcalldata_memory = &self.extcalldata_memory.clone();
        if self.call_type == "STATICCALL" {
            let modifier = match self.gas != WrappedOpcode::new(0x5A, vec![]){
                true => format!("{{ gas: {} }}", self.gas.solidify().cleanup()),
                false => String::from(""),
            };

            format!(
                "address({}).staticcall{}({});",
                self.address.solidify().cleanup(),
                modifier,
                extcalldata_memory
                    .iter()
                    .map(|x| x.operations.solidify().cleanup())
                    .collect::<Vec<String>>()
                    .join(", "),
            )
        } else if self.call_type == "DELEGATECALL" {
            let modifier = match self.gas != WrappedOpcode::new(0x5A, vec![]){
                true => format!("{{ gas: {} }}", self.gas.solidify().cleanup()),
                false => String::from(""),
            };

            format!(
                "address({}).delegatecall{}({});",
                self.address.solidify().cleanup(),
                modifier,
                extcalldata_memory
                    .iter()
                    .map(|x| x.operations.solidify().cleanup())
                    .collect::<Vec<String>>()
                    .join(", "),
            )
        } else if self.call_type == "CALL" || self.call_type == "CALLCODE" {
            let value = match self.value.clone().unwrap() != WrappedOpcode::new(0x5A, vec![]) {
                true => format!("value: {}", self.value.clone().unwrap().solidify().cleanup()),
                false => String::from(""),
            };
            let modifier = match !gas.is_empty() || !value.is_empty() {
                true => format!("{{ {gas}{value} }}"),
                false => String::from(""),
            };
            format!(
                "address({}).call{}({});",
                self.address.solidify().cleanup(),
                modifier,
                extcalldata_memory
                    .iter()
                    .map(|x| x.operations.solidify().cleanup())
                    .collect::<Vec<String>>()
                    .join(", ")
            )
        } else {
            println!("ConcolicExternallCall::to_string() encounters an unknown call type.");
            exit(1);
        }
    }
}


// Implement the Debug trait for A
impl fmt::Debug for ConcolicExternallCall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Write the formatted string to the given formatter
        write!(f, "{}", self.to_string())
    }
}



#[derive(Clone, Debug)]
pub struct BranchSpec {
    // storage structure
    pub storage: HashSet<String>,
    

    // here we should have a storage similar the memory below:
    // however, here we assume the sstore always happens after the sload
    // and no sload happens after the sstore
    // not sure if Solidity compiler has this optimization

    // memory structure:
    //   - key : slot of the argument. I.E: slot 0 is CALLDATALOAD(4).
    //   - value : tuple of ({value: U256, operation: WrappedOpcode})
    pub memory: HashMap<U256, StorageFrame>,

    // holds all found events used to generate solidity error definitions
    // as well as ABI specifications.
    pub events: HashMap<U256, (Option<ResolvedLog>, Log)>,

    // holds all found custom errors used to generate solidity error definitions
    // as well as ABI specifications.
    pub errors: HashMap<U256, Option<ResolvedError>>,

    // stores the matched resolved function for this Functon
    pub resolved_function: Option<ResolvedFunction>,

    // stores strings found within the function
    pub strings: HashSet<String>,

    // store external calls made by the function
    pub external_calls: Vec<String>,

    // store concolic external calls made by the function
    pub concolic_external_calls: Vec<ConcolicExternallCall>,

    // stores addresses found in bytecode
    pub addresses: HashSet<String>,
    
    // control statements, such as access control
    pub control_statement: Option<String>,

    /// concolic control statement, such as access control
    pub concolic_control_statement: Option<WrappedOpcode>,

    // length of children branches must be Two because of JUMPI
    pub children: Vec<Box<BranchSpec>>,

    // this is a revert branch
    pub is_revert: Option<bool>,

    // this is a return branch
    pub is_return: Option<bool>,

    // this is a snippet of the function
    pub start_instruction: Option<u128>,
    pub end_instruction: Option<u128>,
}

// create a new() method for BranchSpec
impl BranchSpec {
    pub fn new() -> Self {
        BranchSpec {
            storage: HashSet::new(),
            memory: HashMap::new(),
            events: HashMap::new(),
            errors: HashMap::new(),
            resolved_function: None,
            strings: HashSet::new(),
            external_calls: Vec::new(),
            concolic_external_calls: Vec::new(),
            addresses: HashSet::new(),
            concolic_control_statement: None,
            control_statement: None,
            children: Vec::new(),
            is_revert: None,
            is_return: None,
            start_instruction: None,
            end_instruction: None,
        }
    }
}


#[derive(Clone, Debug)]
pub struct StorageFrame {
    pub value: U256,
    pub operations: WrappedOpcode,
}

#[derive(Clone, Debug)]
pub struct CalldataFrame {
    pub slot: usize,
    pub operation: String,
    pub mask_size: usize,
    pub heuristics: Vec<String>,
}

impl BranchSpec {
    // get a specific memory slot
    pub fn get_memory_range(&self, _offset: U256, _size: U256) -> Vec<StorageFrame> {
        let mut memory_slice: Vec<StorageFrame> = Vec::new();

        // Safely convert U256 to usize
        let mut offset: usize = std::cmp::min(_offset.try_into().unwrap_or(0), 2048);
        let mut size: usize = std::cmp::min(_size.try_into().unwrap_or(0), 2048);

        // get the memory range
        while size > 0 {
            if let Some(memory) = self.memory.get(&U256::from(offset)) {
                memory_slice.push(memory.clone());
            }
            offset += 32;
            size = size.saturating_sub(32);
        }

        memory_slice
    }

    // fill in both storage and memory load
    // new_wrappedOpcode should initially be 
    #[async_recursion]
    pub async fn fill_in_storage_memory(&self, wrappedOpcode: &mut WrappedOpcode, fetcher: &Fetcher) {
        match wrappedOpcode.opcode.name {
            "SLOAD" => {
                let storage_slot = wrappedOpcode.inputs[0].clone();
                // pub enum WrappedInput {
                //     Raw(U256),
                //     Opcode(WrappedOpcode),
                // }
                match storage_slot {
                    WrappedInput::Raw(slot) => {
                        let value = fetcher.fetch_storage_slot(slot).await;
                        // force convert H256 to U256
                        let bytes: [u8; 32] = value.0;
                        let value_256 = U256::from(bytes);
                        wrappedOpcode.opcode = Opcode::new(0x60); // PUSH1
                        wrappedOpcode.inputs = vec![WrappedInput::Raw(value_256)];
                    }
                    WrappedInput::Opcode( some ) => {
                        if some.opcode.name.starts_with("PUSH") {
                            match some.inputs[0] {
                                WrappedInput::Raw(slot) => {
                                    let value = fetcher.fetch_storage_slot(slot).await;
                                    // force convert H256 to U256
                                    let bytes: [u8; 32] = value.0;
                                    let value_256 = U256::from(bytes);
                                    wrappedOpcode.opcode = Opcode::new(0x60); // PUSH1
                                    wrappedOpcode.inputs = vec![WrappedInput::Raw(value_256)];
                                }
                                WrappedInput::Opcode(_) => {
                                    println!("SLOAD encounters a symbolic slot, instead of a concrete slot.");
                                    println!("The symbolic slot is: {:?}", some.solidify());
                                    exit(1);
                                }
                            }
                        } else if some.solidify().contains("keccak256")  {
                            println!("SLOAD encounters a SHA3 opcode, which is not supported yet.");
                            println!("But it's really a very good sign!")

                        } else {
                            println!("SLOAD encounters a symbolic slot, instead of a concrete slot.");
                            println!("The symbolic slot is 2222: {:?}", some.solidify());
                            exit(1);
                        }
          

                    }
                }
            }
            // "MLOAD" => {}
            _ => {
                for input in wrappedOpcode.inputs.iter_mut() {
                    match input {
                        WrappedInput::Opcode(wrappedOpcode) => {
                            self.fill_in_storage_memory(wrappedOpcode, fetcher).await;
                        }
                        _ => {}
                    }
                }
            }
        }
    }




}
