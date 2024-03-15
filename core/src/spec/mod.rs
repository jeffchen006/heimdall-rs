pub mod analyze;
pub mod structures;
pub mod resolve;

use heimdall_common::{debug_max, utils::threading::run_with_timeout};

use std::{
    collections::{HashMap, HashSet}, process::exit, time::Duration
};

use clap::{AppSettings, Parser};
use derive_builder::Builder;
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
use indicatif::ProgressBar;

use crate::{
    disassemble::{disassemble, DisassemblerArgs},
    spec::{
        resolve::resolve_signatures,
        structures::spec::{BranchSpec, Spec}
    },
};

use crate::cfg::graph::build_cfg;

use crate::spec::analyze::spec_trace;

use petgraph::Graph;

use heimdall_common::ether::evm::ext::exec::VMTrace;





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
pub async fn spec(args: SpecArgs) -> Result<SpecResult, Box<dyn std::error::Error>> {

    // step 1: get the bytecode
    let contract_bytecode = get_bytecode_from_target(&args.target, &args.rpc_url).await?;

    // step 2: perform versioning and compiler heuristics
    let (compiler, version) = detect_compiler(&contract_bytecode);

    // step 3: set up evm
    let evm = VM::new(
        contract_bytecode.clone(),
        String::from("0x"),
        String::from("0x6865696d64616c6c000000000061646472657373"),
        String::from("0x6865696d64616c6c0000000000006f726967696e"),
        String::from("0x6865696d64616c6c00000000000063616c6c6572"),
        0,
        u128::max_value(),
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

    let (selectors, resolved_selectors) =
        get_resolved_selectors(&disassembled_bytecode, &args.skip_resolving, &evm).await?;
    
    // println!("selectors: ");
    // println!("{:?}", selectors);
    // println!("resolved selectors: ");
    // println!("{:?}", resolved_selectors);

    let (specs, all_resolved_errors, all_resolved_events) = get_spec(
        selectors,
        resolved_selectors,
        &contract_bytecode,
        &evm,
        &args,
    )
    .await?;

    for spec in &specs {
        if !spec.pure && !spec.view {
            println!("================");
            println!("selector {:?}", spec.selector);
            print!("resolved: ");
            let mut is_all_pure_or_view = true;
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
                if !spec.pure && !spec.view {
                    is_all_pure_or_view = false;
                }
                if spec.payable {
                    signature.push_str(" payable");
                }
                println!("[{}]{}", ii, signature);
            }
            println!("returns {:?}", spec.returns);

            if is_all_pure_or_view {
                continue;
            }
            

            // println!("arguments {:?}", spec.arguments);
            // println!("storage {:?}", spec.storage);

            // println!("pure {:?}", spec.pure);
            // println!("view {:?}", spec.view);
            // println!("payable {:?}", spec.payable);

            // println!("external calls {:?}", spec.external_calls);
            // println!("control_statements {:?}", spec.control_statements);
            println!("entry_point {:?}", spec.entry_point);

            let head = spec.branch_specs.first().unwrap();
            let head_children = &head.children;


            // assign revert if necessary:
            
            for (i, branch) in spec.branch_specs.iter().enumerate() {
                // if is_revert or control_statement is not None, or addresses is not empty, or external_calls is not empty, or strings is not empty
                if (branch.is_revert.is_some() && branch.is_revert.unwrap()) || 
                        branch.control_statement.is_some() || !branch.addresses.is_empty() || 
                        !branch.external_calls.is_empty() || !branch.strings.is_empty() {
                    println!("================");
                    println!("branch {}", i);
                    println!("storage {:?}", branch.storage);
                    println!("memory {:?}", branch.memory);
                    // println!("events {:?}", branch.events);
                    // println!("errors {:?}", branch.errors);
                    // println!("resolved function {:?}", branch.resolved_function);
                    println!("strings {:?}", branch.strings);
                    println!("external calls {:?}", branch.external_calls);
                    println!("addresses {:?}", branch.addresses);
                    println!("control statement {:?}", branch.control_statement);
                    let num_children = branch.children.len();
                    println!("children {:?}", num_children);
                    if num_children > 0 {
                        if num_children != 2 {
                            println!("branch has more than 2 children");
                            exit(-1);
                        }
                        // -1 for None
                        // 0 for True
                        // 1 for False
                        // 2 for Both
                        let mut revert_branch_index = -1;
                        for (ii, child) in branch.children.iter().enumerate() {
                            if child.is_revert.is_some() && child.is_revert.unwrap() {
                                if revert_branch_index != -1 {
                                    revert_branch_index = 2;
                                } else {
                                    revert_branch_index = ii as i32;
                                }
                            }
                        }
                        if revert_branch_index == 0 {
                            println!("control statement be True to revert");
                        } else if revert_branch_index == 1{
                            println!("control statement be False to revert");
                        } else {
                            println!("will revert any way");
                        }
                    }
                    
                
                    // println!("is revert {:?}", branch.is_revert);                
                }
            }
        }
    }
    Ok(SpecResult {
        specs,
        resolved_errors: all_resolved_errors,
        resolved_events: all_resolved_events,
    })

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
    let mut all_resolved_errors: HashMap<String, ResolvedError> = HashMap::new();
    let mut all_resolved_events: HashMap<String, ResolvedLog> = HashMap::new();
    let mut specs: Vec<Spec> = Vec::new();

    let assertions_on = true;

    for (selector, function_entry_point) in selectors {

        if selector != "1c446983" {
            continue;
        }
        // analyze the function
        // get a map of possible jump destinations
        let mut evm_clone = evm.clone();
        let selector_clone = selector.clone();
        let (map, jumpdest_count) = match run_with_timeout(
            move || evm_clone.symbolic_exec_selector(&selector_clone, function_entry_point),
            Duration::from_millis(args.timeout),
        ) {
            Some(map) => map,
            None => {
                continue
            }
        };
        debug_max!("building spec for selector {} from symbolic execution trace", selector);


        let mut spec = Spec {
            selector: selector.clone(),
            bytecode: decode_hex(&contract_bytecode.replacen("0x", "", 1))?,
            entry_point: function_entry_point,
            arguments: HashMap::new(),
            returns: None,
            pure: true,
            view: true,
            payable: true,
            branch_count: jumpdest_count,              
            cfg_map: HashMap::new(),
            branch_specs: Vec::new(),  
            resolved_function: Vec::new(),
        };

        let mut branchSpec = BranchSpec::new();

        println!("selector {:?}", selector);

        (spec, branchSpec) = spec_trace(&map, spec, branchSpec);


        check_cfg_has_no_broken_edges(&map, &spec);


        if !args.skip_resolving {
            resolve_signatures(
                &mut spec,
                &selector,
                &resolved_selectors,
            )
            .await?;
        }


        // assign revert if necessary:
        while true {
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
                        let condition2 = !branch.children.is_empty() && branch.children[0].is_revert.is_some() && branch.children[0].is_revert.unwrap();
                        let condition3 = !branch.children.is_empty() && branch.children[1].is_revert.is_some() && branch.children[1].is_revert.unwrap();
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
    let key = (first_operation.last_instruction.instruction, last_operation.last_instruction.instruction);


    let mut count: i32 = 0;
    let mut indexes = Vec::new();
    
    for (ii, branch) in spec.branch_specs.iter().enumerate() {
        if branch.start_instruction == Some(key.0) && branch.end_instruction == Some(key.1) {
            count = count + 1;
            indexes.push(ii);
        }
    }

    if count > 1 {
        println!("two branches key already exists, and they are");
        for index in indexes {
            println!("{:?}\n\n", spec.branch_specs.get(index) );
        }
        exit(1);
    }

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