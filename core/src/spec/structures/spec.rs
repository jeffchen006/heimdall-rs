use std::collections::{HashMap, HashSet};

use ethers::types::U256;
use heimdall_common::ether::{
    evm::core::{log::Log, opcodes::WrappedOpcode},
    signatures::{ResolvedError, ResolvedFunction, ResolvedLog},
};

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



#[derive(Clone, Debug)]
pub struct BranchSpec {
    // storage structure
    pub storage: HashSet<String>,

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

    // stores addresses found in bytecode
    pub addresses: HashSet<String>,
    
    // control statements, such as access control
    pub control_statement: Option<String>,

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
            addresses: HashSet::new(),
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
}
