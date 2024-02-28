use std::collections::HashMap;

use super::structures::spec::Spec;
use heimdall_common::{
    debug_max,
    ether::{
        selectors::resolve_selectors,
        signatures::{score_signature, ResolvedError, ResolvedFunction, ResolvedLog},
    },
    utils::{
        io::logging::{Logger, TraceFactory},
        strings::encode_hex_reduced,
    },
};
use indicatif::ProgressBar;

/// Given a list of potential [`ResolvedFunction`]s and a [`Snapshot`], return a list of
/// [`ResolvedFunction`]s (that is, resolved signatures that were found on a 4byte directory) that
/// match the parameters found during symbolic execution for said [`Snapshot`].
pub fn match_parameters(
    resolved_functions: Vec<ResolvedFunction>,
    function: &Spec,
) -> Vec<ResolvedFunction> {
    let mut matched_functions: Vec<ResolvedFunction> = Vec::new();
    for mut resolved_function in resolved_functions {
        debug_max!(
            "checking function {}({}) against Unresolved_0x{}({})",
            &resolved_function.name,
            &resolved_function.inputs.join(","),
            &function.selector,
            &function
                .arguments
                .values()
                .map(|(_, types)| types.first().unwrap().clone())
                .collect::<Vec<String>>()
                .join(",")
        );
        // skip checking if length of parameters list is less than the resolved functions inputs
        resolved_function.inputs.retain(|x| !x.is_empty());
        let mut matched = true;

        // check each parameter type against a list of potential types
        for (index, input) in resolved_function.inputs.iter().enumerate() {
            debug_max!("    checking for parameter {} with type {}", &index.to_string(), &input);
            match function.arguments.get(&index) {
                Some((_, potential_types)) => {
                    // arrays are typically recorded as bytes by the decompiler's potential
                    // types
                    if input.contains("[]") {
                        if !potential_types.contains(&"bytes".to_string()) {
                            debug_max!(
                                "        parameter {} does not match type {} for function {}({})",
                                &index.to_string(),
                                &input,
                                &resolved_function.name,
                                &resolved_function.inputs.join(",")
                            );
                            continue
                        }
                    } else if !potential_types.contains(input) {
                        matched = false;
                        debug_max!(
                            "        parameter {} does not match type {} for function {}({})",
                            &index.to_string(),
                            &input,
                            &resolved_function.name,
                            &resolved_function.inputs.join(",")
                        );
                        break
                    }
                }
                None => {
                    // parameter not found
                    matched = false;
                    debug_max!(
                        "        parameter {} not found for function {}({})",
                        &index.to_string(),
                        &resolved_function.name,
                        &resolved_function.inputs.join(",")
                    );
                    break
                }
            }
        }

        debug_max!("    matched: {}", &matched.to_string());
        if matched {
            matched_functions.push(resolved_function);
        }
    }

    matched_functions
}


// Given a [`Spec`], resolve all the functions 
pub async fn resolve_signatures(
    snapshot: &mut Spec,
    selector: &str,
    resolved_selectors: &HashMap<String, Vec<ResolvedFunction>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let resolved_functions = match resolved_selectors.get(selector) {
        Some(func) => func.clone(),
        None => {
            debug_max!("failed to resolve function signature for selector {}", selector);
            Vec::new()
            
        }
    };
    let mut matched_resolved_functions = match_parameters(resolved_functions, snapshot);

    if matched_resolved_functions.is_empty() {
        debug_max!("no resolved signatures matched this function's parameters");
    } else {
        resolve_function_signatures(
            &mut matched_resolved_functions,
            snapshot,
        )
        .await?;
    }

    Ok(())
}

async fn resolve_function_signatures(
    matched_resolved_functions: &mut Vec<ResolvedFunction>,
    snapshot: &mut Spec,
) -> Result<(), Box<dyn std::error::Error>> {
    // sort matches by signature using score heuristic from `score_signature`
    matched_resolved_functions.sort_by(|a, b| {
        let a_score = score_signature(&a.signature);
        let b_score = score_signature(&b.signature);
        b_score.cmp(&a_score)
    });

    snapshot.resolved_function = matched_resolved_functions.clone();

    debug_max!(
        "{} resolved signature{} matched this function's parameters",
        matched_resolved_functions.len(),
        if matched_resolved_functions.len() > 1 { "s" } else { "" }
    );



    Ok(())
}

