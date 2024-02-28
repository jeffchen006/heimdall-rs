pub mod analyze;
pub mod structures;
pub mod resolve;

use heimdall_common::{debug_max, utils::threading::run_with_timeout};

use std::{
    collections::{HashMap, HashSet},
    time::Duration,
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
    snapshot::{
        structures::snapshot::{GasUsed, Snapshot},
        util::tui,
    },
    spec::{
        resolve::resolve_signatures,
        structures::spec::{BranchSpec, Spec}
    },
};


use crate::spec::analyze::spec_trace;


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

    /// Name for the output snapshot file.
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
    pub snapshots: Vec<Spec>,
    pub resolved_errors: HashMap<String, ResolvedError>,
    pub resolved_events: HashMap<String, ResolvedLog>,
}

/// The main snapshot function, which will be called from the main thread. This module is
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
    
    println!("selectors: ");
    println!("{:?}", selectors);
    println!("resolved selectors: ");
    println!("{:?}", resolved_selectors);

    let (snapshots, all_resolved_errors, all_resolved_events) = get_spec(
        selectors,
        resolved_selectors,
        &contract_bytecode,
        &evm,
        &args,
    )
    .await?;

    for snapshot in &snapshots {
        if !snapshot.pure && !snapshot.view {
            println!("================");
            println!("selector {:?}", snapshot.selector);
            print!("resolved: ");
            for (ii, resolved_function) in snapshot.resolved_function.iter().enumerate() {
                if ii != 0 {
                    print!("      ");
                }
                let mut signature = resolved_function.signature.clone();
                // append pure if snapshot.pure is true
                // append view if snapshot.view is true
                // append payable if snapshot.payable is true
                if snapshot.pure {
                    signature.push_str(" pure");
                }
                if snapshot.view {
                    signature.push_str(" view");
                }
                if snapshot.payable {
                    signature.push_str(" payable");
                }
                println!("[{}]{}", ii, resolved_function.signature);
            }
            println!("returns {:?}", snapshot.returns);
            

            // println!("arguments {:?}", snapshot.arguments);
            // println!("storage {:?}", snapshot.storage);

            // println!("pure {:?}", snapshot.pure);
            // println!("view {:?}", snapshot.view);
            // println!("payable {:?}", snapshot.payable);

            // println!("external calls {:?}", snapshot.external_calls);
            // println!("control_statements {:?}", snapshot.control_statements);
            println!("entry_point {:?}", snapshot.entry_point);


        }
        
    }
    Ok(SpecResult {
        snapshots,
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
            None => {
                continue
            }
        };
        debug_max!("building snapshot for selector {} from symbolic execution trace", selector);


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
            branch_spec: None,  
            resolved_function: Vec::new(),
        };

        let mut branchSpec = BranchSpec::new();

        (spec, branchSpec) = spec_trace(&map, spec, branchSpec);

        spec.branch_spec = Some(branchSpec);

        if !args.skip_resolving {
            resolve_signatures(
                &mut spec,
                &selector,
                &resolved_selectors,
            )
            .await?;
        }

        specs.push(spec);
    }


    Ok((specs, all_resolved_errors, all_resolved_events))
}



