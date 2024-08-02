pub mod analyze;
pub mod resolve;
pub mod structures;

use crate::spec::analyze::spec_trace;
use crate::{
    disassemble::{disassemble, DisassemblerArgs},
    spec::{
        resolve::{args2string, resolve_signatures},
        structures::spec::{BranchSpec, Spec},
    },
};
use clap::{AppSettings, Parser};
use derive_builder::Builder;
use ethers::types::U256;
use heimdall_common::ether::evm::ext::exec::VMTrace;
use heimdall_common::{
    debug_max,
    ether::{
        evm::core::opcodes::WrappedOpcode, lexers::cleanup::Cleanup,
        rpc::get_functions_from_contract,
    },
    utils::{env, threading::run_with_timeout},
};
use heimdall_common::{
    ether::{
        bytecode::get_bytecode_from_target,
        compiler::detect_compiler,
        evm::core::vm::VM,
        selectors::get_resolved_selectors,
        signatures::{ResolvedError, ResolvedFunction, ResolvedLog},
    },
    utils::{
        io::logging::*,
        strings::{decode_hex, get_shortned_target},
    },
};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    env::set_var,
    process::exit,
    time::Duration,
};

#[derive(Debug, Clone, Parser, Builder)]
#[clap(
    about = "Infer function spec from bytecode, including access control, gas consumption, storage accesses, event emissions, and more",
    after_help = "For more information, read the wiki: https://jbecker.dev/r/heimdall-rs/wiki",
    global_setting = AppSettings::DeriveDisplayOrder,
    override_usage = "heimdall spec <TARGET> [OPTIONS]"
)]
pub struct SpecArgs {
    /// The target to analyze. This may be a file, bytecode, or contract address.
    #[clap(required = true)]
    pub target: String,

    /// Set the output verbosity level, 1 - 5.
    #[clap(flatten)]
    pub verbose: clap_verbosity_flag::Verbosity,

    /// The RPC provider to use for fetching target bytecode.
    #[clap(long = "rpc-url", short, default_value = "", hide_default_value = true)]
    pub rpc_url: String,

    /// When prompted, always select the default value.
    #[clap(long, short)]
    pub default: bool,

    /// Whether to skip resolving function selectors.
    #[clap(long = "skip-resolving")]
    pub skip_resolving: bool,

    /// Whether to skip opening the TUI.
    #[clap(long)]
    pub no_tui: bool,

    /// Name for the output spec file.
    #[clap(long, short, default_value = "", hide_default_value = true)]
    pub name: String,

    /// The output directory to write the output to, or 'print' to print to the console.
    #[clap(long = "output", short = 'o', default_value = "output", hide_default_value = true)]
    pub output: String,

    /// The timeout for each function's symbolic execution in milliseconds.
    #[clap(long, short, default_value = "10000", hide_default_value = true)]
    pub timeout: u64,
}

impl Default for SpecArgs {
    fn default() -> Self {
        SpecArgs {
            target: String::new(),
            verbose: clap_verbosity_flag::Verbosity::new(0, 1),
            rpc_url: String::from("https://eth.llamarpc.com"),
            default: true,
            skip_resolving: false,
            no_tui: true,
            name: String::new(),
            output: String::new(),
            timeout: 10000,
        }
    }
}

impl SpecArgsBuilder {
    pub fn new() -> Self {
        SpecArgsBuilder {
            target: Some(String::new()),
            verbose: Some(clap_verbosity_flag::Verbosity::new(0, 1)),
            rpc_url: Some(String::new()),
            default: Some(true),
            skip_resolving: Some(false),
            no_tui: Some(true),
            name: Some(String::new()),
            output: Some(String::new()),
            timeout: Some(10000),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SpecResult {
    pub specs: Vec<Spec>,
    pub resolved_errors: HashMap<String, ResolvedError>,
    pub resolved_events: HashMap<String, ResolvedLog>,
}

/// The main spec function, which will be called from the main thread. This module is
/// responsible for generating a high-level overview of the target contract, including function
/// signatures, access control, gas consumption, storage accesses, event emissions, and more.
pub async fn spec(
    args: SpecArgs,
    selectors_interested: Vec<String>,
) -> Result<SpecResult, Box<dyn std::error::Error>> {
    // step 1: get the bytecode
    let contract_bytecode = get_bytecode_from_target(&args.target, &args.rpc_url).await?;

    // step 2: perform versioning and compiler heuristics
    let (compiler, version) = detect_compiler(&contract_bytecode);

    // print the bytecode:
    println!("bytecode: {:?}", contract_bytecode);
    // step 3: set up evm
    let evm = VM::new(
        contract_bytecode.clone(),
        String::from("0x"),
        String::from("0x6865696d64616c6c000000000061646472657373"),
        String::from("0x6865696d64616c6c0000000000006f726967696e"),
        String::from("0x6865696d64616c6c00000000000063616c6c6572"),
        0,
        u128::MAX,
    );

    // step 4: disassemble the bytecode
    let disassembled_bytecode = disassemble(DisassemblerArgs {
        rpc_url: args.rpc_url.clone(),
        verbose: args.verbose.clone(),
        target: args.target.clone(),
        name: args.name.clone(),
        decimal_counter: false,
        output: String::new(),
    })
    .await?;

    // step 5: resolve the selectors and signatures (optional)
    let (selectors, resolved_selectors) =
        get_resolved_selectors(&disassembled_bytecode, &args.skip_resolving, &evm).await?;

    // step 6: set up onchain fetcher => skipped

    // step 7: get the spec
    let (specs, all_resolved_errors, all_resolved_events) =
        get_spec(selectors, resolved_selectors, &contract_bytecode, &evm, &args).await?;

    // step 8: get contract from EtherScan if verified on EtherScan
    set_var("ETHERSCAN_API_KEY", "I7R59ER7AQ8HEBYTNR15ETXJSMTD86BHA4");
    let ret = get_functions_from_contract(&args.target).await;
    let selector_map = match ret {
        Ok(functions) => functions,
        Err(_) => BTreeMap::new(),
    };

    // step 9: print function specifications,
    // if open sourced, print the function signature
    // if close sourced, print the function signature resolved
    for spec in &specs {
        // if spec.selector not in selectorsInterested
        // check whether length of selectors_interested is 0
        // if it is, print all functions

        if selectors_interested.len() != 0 && !selectors_interested.contains(&spec.selector) {
            continue;
        }

        if !spec.pure && !spec.view {
            println!("================");
            print!("selector: {:?}", spec.selector);

            // check if spec.selector is in selector_map
            if selector_map.contains_key(&spec.selector) {
                println!(" Open Sourced:  ");
                let function = selector_map.get(&spec.selector).unwrap();
                // println!("function name: {:?}", function.name);
                // println!("function inputs: {:?}", function.inputs);
                // println!("function outputs: {:?}", function.outputs);
                println!("{:?}", function.signature())
            } else {
                println!("Close Sourced:  ");
                println!("args: {:?}", spec.arguments);
                println!("arguments: {:?}", args2string(&spec.arguments));
                println!("resolved: ");
                for (ii, resolved_function) in spec.resolved_function.iter().enumerate() {
                    if ii != 0 {
                        print!("      ");
                    }
                    let mut signature = resolved_function.signature.clone();
                    // append pure if spec.pure is true
                    // append view if spec.view is true
                    // append payable if spec.payable is true
                    if spec.pure {
                        signature.push_str(" pure");
                    }
                    if spec.view {
                        signature.push_str(" view");
                    }
                    if spec.payable {
                        signature.push_str(" payable");
                    }
                    println!("[{}]{}", ii, signature);
                }
                println!("returns {:?}", spec.returns);
            }
            // if spec.pure && spec.view {
            //     continue;
            // }
            // println!("arguments {:?}", spec.arguments);
            // println!("storage {:?}", spec.storage);
            println!("pure {:?}", spec.pure);
            println!("view {:?}", spec.view);
            println!("payable {:?}", spec.payable);
            // println!("external calls {:?}", spec.external_calls);
            // println!("control_statements {:?}", spec.control_statements);
            println!("entry_point {:?}", spec.entry_point);
            let mut head = spec.branch_specs.first().unwrap();
            let mut head_found = false;
            // find head
            for branch in spec.branch_specs.iter() {
                if branch.start_instruction.is_some()
                    && branch.start_instruction.unwrap() == spec.entry_point + 1
                {
                    head = branch;
                    head_found = true;
                    // break;
                }

                if branch.is_revert.is_some() && branch.is_revert.unwrap() {
                    continue;
                } else if branch.children.len() == 2 {
                    // check if there is a branch with two children that are both revert
                    if branch.children[0].is_revert.is_some()
                        && branch.children[0].is_revert.unwrap()
                        && branch.children[1].is_revert.is_some()
                        && branch.children[1].is_revert.unwrap()
                    {
                        println!("branch has two children that are both revert");
                        // this error should be fixed in get_spec()
                        exit(-1);
                    }
                }
            }
            if !head_found {
                println!("head not found");
                exit(-1);
            }

            // check for reentrancy guard
            if has_reentrancy_guard(head) {
                println!("reentrancy guard found");
                // todo: set reentrancy guard in spec
            } else {
                println!("no reentrancy guard found");
            }

            // Traverse the tree without recursion using a stack
            let mut stack = Vec::new();
            stack.push(head);
            while let Some(branch) = stack.pop() {
                for child in branch.children.iter() {
                    stack.push(child);
                }
            }

            // for child in head.children.iter() {
            //     println!("child selector {:?}", child);
            // }

            // we should have a smarter way to print it:
            println!("branch count {:?}", spec.branch_count);

            // two tags we must have:
            // 1. arbitrary external call
            // this can be told be checking whether there exists an external call with arguments in the branch

            // 2. which branch has which storage accesses and external calls
            // absolutely will happen:
            // possibly will happen:  [ (storageAccess, [branch1, branch2]), (storageAccess, [branch1, branch2]) ]

            let mut stack: Vec<&BranchSpec> = Vec::new();
            stack.push(head);

            // status stack to keep track of whether a branch will certainly be executed
            // or possibly be executed
            let mut status_stack: Vec<bool> = Vec::new();
            status_stack.push(true);

            let mut used_control_statements: HashSet<_> = HashSet::new();
            let mut absolute_storage_reads: HashSet<String> = HashSet::new();
            let mut possible_storage_writes: HashSet<String> = HashSet::new();
            let mut absolute_external_calls: Vec<String> = Vec::new();
            let mut possible_external_calls: Vec<String> = Vec::new();

            while let Some(branch) = stack.pop() {
                let status = status_stack.pop().unwrap();
                if status {
                    absolute_storage_reads.extend(branch.storage_reads.clone());
                    absolute_external_calls.extend(branch.external_calls.clone());
                } else {
                    if branch.control_statement.is_some() {
                        used_control_statements.insert(branch.control_statement.clone().unwrap());
                    }
                    possible_storage_writes.extend(branch.storage_writes.clone());
                    possible_external_calls.extend(branch.external_calls.clone());
                }

                let mut is_one_child_revert = false;
                let mut revert_child = 9;
                if branch.children.len() == 2 {
                    if branch.children[0].is_revert.is_some()
                        && branch.children[0].is_revert.unwrap()
                        && branch.children[1].is_revert.is_some()
                        && !branch.children[1].is_revert.unwrap()
                    {
                        is_one_child_revert = true;
                        revert_child = 0;
                    } else if branch.children[1].is_revert.is_some()
                        && branch.children[1].is_revert.unwrap()
                        && branch.children[0].is_revert.is_some()
                        && !branch.children[0].is_revert.unwrap()
                    {
                        is_one_child_revert = true;
                        revert_child = 1;
                    }
                }

                if !is_one_child_revert {
                    for child in branch.children.iter() {
                        stack.push(child);
                        status_stack.push(status);
                    }
                } else {
                    stack.push(&branch.children[revert_child]);
                    status_stack.push(status);

                    stack.push(&branch.children[1 - revert_child]);
                    status_stack.push(false);
                }
            }

            // print used_control_statements, absolute_storage_reads, possible_storage_writes, absolute_external_calls, possible_external_calls
            println!("used control statements: {:?}", used_control_statements);
            println!("absolute storage reads: {:?}", absolute_storage_reads);
            println!("possible storage writes: {:?}", possible_storage_writes);
            println!("all possible storage reads: {:?}", spec.storage_read);
            println!("all possible storage writes: {:?}", spec.storage_write);
            println!("absolute external calls: {:?}", absolute_external_calls);
            println!("possible external calls: {:?}", possible_external_calls);
            println!("all possible external calls: {:?}", spec.external_calls);
        }
    }

    Ok(SpecResult {
        specs,
        resolved_errors: all_resolved_errors,
        resolved_events: all_resolved_events,
    })
}

fn has_reentrancy_guard(branch: &BranchSpec) -> bool {
    for value_read in branch.storage_reads_values.iter() {
        let mut failed = false;
        for child in branch.children.iter() {
            if (child.is_revert.is_some() && child.is_revert.unwrap())
                || (child.is_loop.is_some() && child.is_loop.unwrap())
            {
                continue;
            }
            if !rewrites_value_to_storage(child, &value_read.address, &value_read.value) {
                failed = true;
                break;
            }
        }
        if !failed {
            println!(
                "possible reentrancy guard found at using the value at slot {:?}",
                value_read.address
            );
            return true;
        }
    }

    if branch.children.is_empty() {
        return false;
    }

    for child in branch.children.iter() {
        if (child.is_revert.is_some() && !child.is_revert.unwrap())
            && (child.is_loop.is_some() && !child.is_loop.unwrap())
            && has_reentrancy_guard(child)
        {
            return true;
        }
    }
    false
}

fn rewrites_value_to_storage(branch: &BranchSpec, address: &str, initial_value: &U256) -> bool {
    for ii in 0..branch.storage_writes_values.len() {
        let value_write = &branch.storage_writes_values[ii];
        if value_write.address == address && value_write.value != *initial_value {
            // the recovery might be in the same branch or in the children
            if recovers_value(branch, address, initial_value, ii + 1) {
                return true;
            }
        }
    }

    if branch.children.is_empty() {
        return false;
    }

    let mut failed = false;
    for child in branch.children.iter() {
        if (child.is_revert.is_some() && child.is_revert.unwrap())
            || (child.is_loop.is_some() && child.is_loop.unwrap())
        {
            continue;
        }
        if !rewrites_value_to_storage(child, address, initial_value) {
            failed = true;
            break;
        }
    }
    !failed
}

fn recovers_value(
    branch: &BranchSpec,
    address: &str,
    initial_value: &U256,
    start_idx: usize,
) -> bool {
    for ii in start_idx..branch.storage_writes_values.len() {
        let value_write = &branch.storage_writes_values[ii];
        if value_write.address == address && value_write.value == *initial_value {
            return true;
        }
    }

    if branch.children.is_empty() {
        return false;
    }

    let mut failed = false;
    for child in branch.children.iter() {
        if (child.is_revert.is_some() && child.is_revert.unwrap())
            || (child.is_loop.is_some() && child.is_loop.unwrap())
        {
            continue;
        }
        if !recovers_value(child, address, initial_value, 0) {
            failed = true;
            break;
        }
    }
    !failed
}

async fn get_spec(
    selectors: HashMap<String, u128>,
    resolved_selectors: HashMap<String, Vec<ResolvedFunction>>,
    contract_bytecode: &str,
    evm: &VM,
    args: &SpecArgs,
) -> Result<
    (Vec<Spec>, HashMap<String, ResolvedError>, HashMap<String, ResolvedLog>),
    Box<dyn std::error::Error>,
> {
    let all_resolved_errors: HashMap<String, ResolvedError> = HashMap::new();
    let all_resolved_events: HashMap<String, ResolvedLog> = HashMap::new();
    let mut specs: Vec<Spec> = Vec::new();

    let assertions_on = true;

    for (selector, function_entry_point) in selectors {
        // analyze the function
        // get a map of possible jump destinations
        let mut evm_clone = evm.clone();
        let selector_clone = selector.clone();
        let (map, jumpdest_count) = match run_with_timeout(
            move || evm_clone.symbolic_exec_selector(&selector_clone, function_entry_point),
            Duration::from_millis(args.timeout),
        ) {
            Some(map) => map,
            None => continue,
        };
        debug_max!("building spec for selector {} from symbolic execution trace", selector);

        let mut spec = Spec {
            selector: selector.clone(),
            bytecode: decode_hex(&contract_bytecode.replacen("0x", "", 1))?,
            entry_point: function_entry_point,
            arguments: HashMap::new(),
            storage_read: HashSet::new(),
            storage_write: HashSet::new(),
            external_calls: Vec::new(),

            memory: HashMap::new(),
            returns: None,
            pure: true,
            view: true,
            payable: true,
            branch_count: jumpdest_count,
            cfg_map: HashMap::new(),
            branch_specs: Vec::new(),
            resolved_function: Vec::new(),
            contains_reentrancy_guard: false,
        };

        let mut branch_spec = BranchSpec::new();

        println!("selector {:?}", selector);

        (spec, branch_spec) = spec_trace(&map, spec, branch_spec).await;

        check_cfg_has_no_broken_edges(&map, &spec);

        if !args.skip_resolving {
            resolve_signatures(&mut spec, &selector, &resolved_selectors).await?;
        }

        // for branch in spec.branch_specs.iter() {
        //     if branch.is_revert.is_some() && branch.is_revert.unwrap() {
        //         println!("branch has revert");
        //     } else if branch.is_return.is_some() && branch.is_return.unwrap() {
        //         println!("branch has return");
        //     } else if branch.children.is_empty() {
        //         println!("branch has no return or revert");
        //     }
        // }

        // assign revert if necessary:
        loop {
            let mut is_stop = true;
            for branch in spec.branch_specs.iter_mut() {
                // if ii == 10 && spec.selector == "06fdd603"{ check and unwrap in one step
                if let Some(true) = branch.is_revert {
                    continue;
                }
                if !branch.children.is_empty() {
                    let mut is_all_revert = true;
                    for child in &branch.children {
                        // Again, use `if let` for more idiomatic Rust code
                        if let Some(false) = child.is_revert {
                            is_all_revert = false;
                            break;
                        }
                    }
                    if is_all_revert {
                        branch.is_revert = Some(true);
                        is_stop = false;
                    }
                }
            }

            if is_stop {
                if assertions_on {
                    for branch in spec.branch_specs.iter() {
                        let condition1 = !branch.is_revert.unwrap();
                        let condition2 = !branch.children.is_empty()
                            && branch.children[0].is_revert.is_some()
                            && branch.children[0].is_revert.unwrap();
                        let condition3 = !branch.children.is_empty()
                            && branch.children[1].is_revert.is_some()
                            && branch.children[1].is_revert.unwrap();
                        if condition1 && condition2 && condition3 {
                            println!("branch has all children revert hahahaha");
                            exit(-1);
                        }
                    }
                }
                break;
            }
        }

        specs.push(spec);
    }

    Ok((specs, all_resolved_errors, all_resolved_events))
}

// also to help understand the cfg
fn check_cfg_has_no_broken_edges(vm_trace: &VMTrace, spec: &Spec) {
    // print last operation of vm_trace.operations
    let last_operation = vm_trace.operations.last().unwrap();
    let first_operation = vm_trace.operations.first().unwrap();
    let key =
        (first_operation.last_instruction.instruction, last_operation.last_instruction.instruction);

    let mut count: i32 = 0;
    let mut indexes = Vec::new();

    for (ii, branch) in spec.branch_specs.iter().enumerate() {
        if branch.start_instruction == Some(key.0) && branch.end_instruction == Some(key.1) {
            count = count + 1;
            indexes.push(ii);
        }
    }

    //// Nothing surprising here
    // if count > 1 {
    //     for index in indexes {
    //         println!("{:?}\n\n", spec.branch_specs.get(index) );
    //     }
    //     println!("Two same branches are found in the spec, meaning there is a cyclic path in the cfg");
    //     // exit(1);
    // }

    for child in vm_trace.children.iter() {
        check_cfg_has_no_broken_edges(child, &spec);
    }

    // let is_step_in = false;
    // if spec.cfg_map.contains_key(&key) {
    //     println!("key already exists");
    //     exit(1);
    // }

    // if !spec.cfg_map.contains_key(&key) {
    //     // check
    //     if vm_trace.children.len() == 2 {
    //         if branchSpec.control_statement == None {
    //             println!("impossible, reach a branch with two children and no control statement");
    //             exit(1);
    //         }
    //     } else if vm_trace.children.len() == 0 {
    //         if branchSpec.control_statement != None {
    //             println!("impossible, reach a branch with no children and a control statement");

    //             println!("control statement: {:?}", branchSpec.control_statement);

    //             println!("operations:");
    //             vm_trace.pretty_print_trace();

    //             // // build hashable jump frame
    //             // let jump_frame = JumpFrame::new(
    //             //     state.last_instruction.instruction,
    //             //     state.last_instruction.inputs[0],
    //             //     vm.stack.size(),
    //             //     jump_taken,
    //             // );

    //             // locate jump frame in the graph
    //             let last_instruction = vm_trace.operations.last().unwrap().last_instruction.clone();
    //             let aa = last_instruction.instruction;
    //             let inputs0 = last_instruction.inputs[0];

    //             println!("I care {:?}", aa);
    //             println!("I care {:?}", inputs0);

    //             println!("impossible, reach a branch with no children and a control statement");
    //             exit(1);

    //         }
    //     } else {
    //         println!("not two children");
    //         exit(1);
    //     }
    //     spec.cfg_map.insert(
    //         key,
    //         Vec::new(),
    //     );
    // } else {

    // }
}
