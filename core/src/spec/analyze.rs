use std::process::exit;

use crate::decompile::constants::AND_BITMASK_REGEX;

use crate::snapshot::{
    constants::VARIABLE_SIZE_CHECK_REGEX
};

use crate::spec::structures::spec::{Spec, BranchSpec, CalldataFrame, StorageFrame};

use ethers::{
    abi::{decode, ParamType},
    types::U256,
};
use heimdall_common::debug_max;
use heimdall_common::{
    ether::{
        evm::{
            core::{
                opcodes::WrappedOpcode,
                types::{byte_size_to_type, convert_bitmask},
            },
            ext::exec::VMTrace,
        },
        lexers::cleanup::Cleanup,
    },
    utils::{io::logging::TraceFactory, strings::encode_hex_reduced},
};

/// Generates a spec of a VMTrace's underlying function
///
/// ## Parameters
/// - `vm_trace` - The VMTrace to be analyzed
/// - `spec` - The spec to be updated with the analysis results
/// - `trace` - The TraceFactory to be updated with the analysis results
/// - `trace_parent` - The parent of the current VMTrace
///
/// ## Returns
/// - `spec` - The updated spec
pub fn spec_trace(
    vm_trace: &VMTrace,
    spec: Spec,
    branch_spec: BranchSpec,
) -> (Spec, BranchSpec) {
    // make a clone of the recursed analysis function
    let mut spec = spec;
    let mut branchSpec = branch_spec;
    
    branchSpec.start_instruction = Some(vm_trace.operations.first().unwrap().last_instruction.instruction);
    branchSpec.end_instruction = Some(vm_trace.operations.last().unwrap().last_instruction.instruction);


    // perform analysis on the operations of the current VMTrace branch
    for operation in &vm_trace.operations {
        let instruction = operation.last_instruction.clone();
        let _storage = operation.storage.clone();
        let memory = operation.memory.clone();

        let opcode_name = instruction.opcode_details.clone().unwrap().name;
        let opcode_number = instruction.opcode;

        // if the instruction is a state-accessing instruction, the function is no longer pure
        if spec.pure &&
            vec![
                "BALANCE",
                "ORIGIN",
                "CALLER",
                "GASPRICE",
                "EXTCODESIZE",
                "EXTCODECOPY",
                "BLOCKHASH",
                "COINBASE",
                "TIMESTAMP",
                "NUMBER",
                "DIFFICULTY",
                "GASLIMIT",
                "CHAINID",
                "SELFBALANCE",
                "BASEFEE",
                "SLOAD",
                "SSTORE",
                "CREATE",
                "SELFDESTRUCT",
                "CALL",
                "CALLCODE",
                "DELEGATECALL",
                "STATICCALL",
                "CREATE2",
            ]
            .contains(&opcode_name)
        {
            spec.pure = false;
        }

        // if the instruction is a state-setting instruction, the function is no longer a view
        if spec.view &&
            [
                "SSTORE",
                "CREATE",
                "SELFDESTRUCT",
                "CALL",
                "CALLCODE",
                "DELEGATECALL",
                "STATICCALL",
                "CREATE2",
            ]
            .contains(&opcode_name)
        {
            spec.view = false;
        }

        if (0xA0..=0xA4).contains(&opcode_number) {
            // LOG0, LOG1, LOG2, LOG3, LOG4
            let logged_event = match operation.events.last() {
                Some(event) => event,
                None => continue,
            };

            // check to see if the event is a duplicate
            if !branchSpec
                .events
                .iter()
                .any(|(selector, _)| selector == logged_event.topics.first().unwrap())
            {
                // add the event to the function
                branchSpec
                    .events
                    .insert(*logged_event.topics.first().unwrap(), (None, logged_event.clone()));
            }
            
        } else if opcode_name == "JUMPI" {
            // this is an if conditional for the children branches
            let conditional = instruction.input_operations[1].solidify().cleanup();
            // if conditional.contains("memory") {
            //     // println!("now is the time");
            //     println!("{:?}", conditional);
            //     // print input_operations
            //     for op in instruction.input_operations.iter() {
            //         println!("{:?}", op);
            //     }
            // }
            let symbolic_conditional = instruction.input_operations[1].clone();


            let jump_taken = instruction.inputs.get(1).map(|op| !op.is_zero()).unwrap_or(true);
            let jump_dest = instruction.inputs[0];

            // println!("JUMPI conditional: {:?}", conditional);
            // println!("JUMPI jump_taken: {:?}", jump_taken);
            // println!("JUMPI jump_dest: {:?}", jump_dest);

            // remove non-payable check and mark function as non-payable
            if conditional == "!msg.value" {
                // this is marking the start of a non-payable function
                spec.payable = false;
                branchSpec.control_statement = Some(format!("if ({}) {{ .. }}", conditional));
                branchSpec.symbolic_control_statement = Some(symbolic_conditional);
                continue
            }

            // perform a series of checks to determine if the condition
            // is added by the compiler and can be ignored
            if (conditional.contains("msg.data.length") && conditional.contains("0x04")) ||
                VARIABLE_SIZE_CHECK_REGEX.is_match(&conditional).unwrap_or(false) ||
                (conditional.replace('!', "") == "success") ||
                (!conditional.contains("msg.sender") &&
                    !conditional.contains("arg") &&
                    !conditional.contains("storage"))
            {

                branchSpec.control_statement = Some(format!("if ({}) {{ .. }}", conditional));
                branchSpec.symbolic_control_statement = Some(symbolic_conditional);
                continue
            }

            if branchSpec.control_statement != None {
                // report an error
                println!("Error: multiple control statements in a single function");
                exit(1);
            }
            branchSpec.control_statement = Some(format!("if ({}) {{ .. }}", conditional));
            branchSpec.symbolic_control_statement = Some(symbolic_conditional);


        } else if opcode_name == "REVERT" {
            // Safely convert U256 to usize
            let offset: usize = instruction.inputs[0].try_into().unwrap_or(0);
            let size: usize = instruction.inputs[1].try_into().unwrap_or(0);
            let revert_data: Vec<u8> = memory.read(offset, size);
            branchSpec.is_revert = Some(true);

            if let Some(hex_data) = revert_data.get(4..) {
                if let Ok(reverts_with) = decode(&[ParamType::String], hex_data) {
                    if !reverts_with[0].to_string().is_empty() &&
                        reverts_with[0].to_string().chars().all(|c| c != '\0')
                    {
                        branchSpec.strings.insert(reverts_with[0].to_string().to_owned());
                    }
                }
            }

        } else if opcode_name == "RETURN" {
            // Safely convert U256 to usize
            let offset: usize = instruction.inputs[0].try_into().unwrap_or(0);
            let size: usize = instruction.inputs[1].try_into().unwrap_or(0);
            let return_data = memory.read(offset, size);
            branchSpec.is_return = Some(true);

            if let Some(hex_data) = return_data.get(4..) {
                if let Ok(returns) = decode(&[ParamType::String], hex_data) {
                    if !returns[0].to_string().is_empty() &&
                        returns[0].to_string().chars().all(|c| c != '\0')
                    {
                        branchSpec.strings.insert(returns[0].to_string());
                    }
                }
            }

            let return_memory_operations =
                branchSpec.get_memory_range(instruction.inputs[0], instruction.inputs[1]);
            let return_memory_operations_solidified = return_memory_operations
                .iter()
                .map(|x| x.operations.solidify().cleanup())
                .collect::<Vec<String>>()
                .join(", ");

            // we don't want to overwrite the return value if it's already been set
            if spec.returns == Some(String::from("uint256")) || spec.returns.is_none() {
                // if the return operation == ISZERO, this is a boolean return
                if return_memory_operations.len() == 1 &&
                    return_memory_operations[0].operations.opcode.name == "ISZERO"
                {
                    spec.returns = Some(String::from("bool"));
                } else {
                    spec.returns = match size > 32 {
                        // if the return data is > 32 bytes, we append "memory" to the return
                        // type
                        true => Some(format!("{} memory", "bytes")),
                        false => {
                            // attempt to find a return type within the return memory operations
                            let byte_size = match AND_BITMASK_REGEX
                                .find(&return_memory_operations_solidified)
                                .unwrap()
                            {
                                Some(bitmask) => {
                                    let cast = bitmask.as_str();

                                    cast.matches("ff").count()
                                }
                                None => 32,
                            };

                            // convert the cast size to a string
                            let (_, cast_types) = byte_size_to_type(byte_size);
                            Some(cast_types[0].to_string())
                        }
                    };
                }
            }
        } else if opcode_name == "SSTORE" || opcode_name == "SLOAD" {
            branchSpec.storage.insert(instruction.input_operations[0].solidify().cleanup());
        } else if opcode_name == "CALLDATALOAD" {
            let slot_as_usize: usize = instruction.inputs[0].try_into().unwrap_or(usize::MAX);
            let calldata_slot = (slot_as_usize.saturating_sub(4)) / 32;
            match spec.arguments.get(&calldata_slot) {
                Some(_) => {}
                None => {
                    spec.arguments.insert(
                        calldata_slot,
                        (
                            CalldataFrame {
                                slot: calldata_slot,
                                operation: instruction.input_operations[0].to_string(),
                                mask_size: 32,
                                heuristics: Vec::new(),
                            },
                            vec![
                                "bytes".to_string(),
                                "uint256".to_string(),
                                "int256".to_string(),
                                "string".to_string(),
                                "bytes32".to_string(),
                                "uint".to_string(),
                                "int".to_string(),
                            ],
                        ),
                    );
                }
            }
        } else if opcode_name == "ISZERO" {
            if let Some(calldata_slot_operation) = instruction
                .input_operations
                .iter()
                .find(|operation| operation.opcode.name == "CALLDATALOAD")
            {
                if let Some((calldata_slot, arg)) =
                    spec.arguments.clone().iter().find(|(_, (frame, _))| {
                        frame.operation == calldata_slot_operation.inputs[0].to_string()
                    })
                {
                    // copy the current potential types to a new vector and remove duplicates
                    let mut potential_types = vec![
                        "bool".to_string(),
                        "bytes1".to_string(),
                        "uint8".to_string(),
                        "int8".to_string(),
                    ];
                    potential_types.append(&mut arg.1.clone());
                    potential_types.sort();
                    potential_types.dedup();

                    // replace mask size and potential types
                    spec.arguments.insert(*calldata_slot, (arg.0.clone(), potential_types));
                }
            };
        } else if ["AND", "OR"].contains(&opcode_name) {
            // convert the bitmask to it's potential solidity types
            let (mask_size_bytes, mut potential_types) = convert_bitmask(instruction.clone());

            for (i, operation) in instruction.input_operations.iter().enumerate() {
                // check for PUSH operations
                if operation.opcode.name.starts_with("PUSH") {
                    let address = encode_hex_reduced(instruction.inputs[i]);

                    // this parameter is not likely to be an address because:
                    // 1. if the address contains only Fs and 0s, it's likely a bitwise mask
                    // 2. if the address is not 32 or 20 bytes, it's likely a bitwise mask
                    if address.replacen("0x", "", 1).chars().all(|c| c == 'f' || c == '0') ||
                        (address.len() > 42 || address.len() < 32)
                    {
                        continue
                    }

                    branchSpec.addresses.insert(address);
                }
            }

            if let Some(calldata_slot_operation) =
                instruction.input_operations.iter().find(|operation| {
                    operation.opcode.name == "CALLDATALOAD" ||
                        operation.opcode.name == "CALLDATACOPY"
                })
            {
                if let Some((calldata_slot, arg)) =
                    spec.arguments.clone().iter().find(|(_, (frame, _))| {
                        frame.operation == calldata_slot_operation.inputs[0].to_string()
                    })
                {
                    // append the current potential types to the new vector and remove
                    // duplicates
                    potential_types.append(&mut arg.1.clone());
                    potential_types.sort();
                    potential_types.dedup();

                    // replace mask size and potential types
                    spec.arguments.insert(
                        *calldata_slot,
                        (
                            CalldataFrame {
                                slot: arg.0.slot,
                                operation: arg.0.operation.clone(),
                                mask_size: mask_size_bytes,
                                heuristics: Vec::new(),
                            },
                            potential_types,
                        ),
                    );
                }
            };
        } else if opcode_name.contains("MSTORE") {
            let key = instruction.inputs[0];
            let value = instruction.inputs[1];
            let operation = instruction.input_operations[1].clone();

            // add the mstore to the function's memory map
            branchSpec.memory.insert(key, StorageFrame { value, operations: operation });
        } else if opcode_name == "CODECOPY" {
            let memory_offset = &instruction.inputs[0];
            let source_offset = instruction.inputs[1].try_into().unwrap_or(usize::MAX);
            let size_bytes = instruction.inputs[2].try_into().unwrap_or(usize::MAX);

            // get the code from the source offset and size
            let code = spec.bytecode[source_offset..(source_offset + size_bytes)].to_vec();

            // add the code to the function's memory map in chunks of 32 bytes
            for (index, chunk) in code.chunks(32).enumerate() {
                let key = memory_offset + (index * 32);
                let value = U256::from_big_endian(chunk);

                branchSpec.memory.insert(
                    key,
                    StorageFrame { value, operations: WrappedOpcode::new(0x39, vec![]) },
                );
            }
        } else if opcode_name == "STATICCALL" {
            // if the gas param WrappedOpcode is not GAS(), add the gas param to the function's
            // logic
            let modifier = match instruction.input_operations[0] != WrappedOpcode::new(0x5A, vec![])
            {
                true => {
                    format!("{{ gas: {} }}", instruction.input_operations[0].solidify().cleanup())
                }
                false => String::from(""),
            };

            let address = &instruction.input_operations[1];
            let extcalldata_memory =
                branchSpec.get_memory_range(instruction.inputs[2], instruction.inputs[3]);

            branchSpec.external_calls.push(format!(
                "address({}).staticcall{}({});",
                address.solidify().cleanup(),
                modifier,
                extcalldata_memory
                    .iter()
                    .map(|x| x.operations.solidify().cleanup())
                    .collect::<Vec<String>>()
                    .join(", "),
            ));
        } else if opcode_name == "DELEGATECALL" {
            // if the gas param WrappedOpcode is not GAS(), add the gas param to the function's
            // logic
            let modifier = match instruction.input_operations[0] != WrappedOpcode::new(0x5A, vec![])
            {
                true => {
                    format!("{{ gas: {} }}", instruction.input_operations[0].solidify().cleanup())
                }
                false => String::from(""),
            };

            let address = &instruction.input_operations[1];
            let extcalldata_memory =
                branchSpec.get_memory_range(instruction.inputs[2], instruction.inputs[3]);

            branchSpec.external_calls.push(format!(
                "address({}).delegatecall{}({});",
                address.solidify().cleanup(),
                modifier,
                extcalldata_memory
                    .iter()
                    .map(|x| x.operations.solidify().cleanup())
                    .collect::<Vec<String>>()
                    .join(", "),
            ));
        } else if opcode_name == "CALL" || opcode_name == "CALLCODE" {
            // if the gas param WrappedOpcode is not GAS(), add the gas param to the function's
            // logic
            let gas = match instruction.input_operations[0] != WrappedOpcode::new(0x5A, vec![]) {
                true => format!("gas: {}, ", instruction.input_operations[0].solidify().cleanup()),
                false => String::from(""),
            };
            let value = match instruction.input_operations[2] != WrappedOpcode::new(0x5A, vec![]) {
                true => format!("value: {}", instruction.input_operations[2].solidify().cleanup()),
                false => String::from(""),
            };
            let modifier = match !gas.is_empty() || !value.is_empty() {
                true => format!("{{ {gas}{value} }}"),
                false => String::from(""),
            };

            let address = &instruction.input_operations[1];
            let extcalldata_memory =
                branchSpec.get_memory_range(instruction.inputs[3], instruction.inputs[4]);

            branchSpec.external_calls.push(format!(
                "address({}).call{}({});",
                address.solidify().cleanup(),
                modifier,
                extcalldata_memory
                    .iter()
                    .map(|x| x.operations.solidify().cleanup())
                    .collect::<Vec<String>>()
                    .join(", ")
            ));
        }

        // handle type heuristics
        if [
            "MUL",
            "MULMOD",
            "ADDMOD",
            "SMOD",
            "MOD",
            "DIV",
            "SDIV",
            "EXP",
            "LT",
            "GT",
            "SLT",
            "SGT",
            "SIGNEXTEND",
        ]
        .contains(&opcode_name)
        {
            // get the calldata slot operation
            if let Some((key, (frame, potential_types))) =
                spec.arguments.clone().iter().find(|(_, (frame, _))| {
                    instruction.output_operations.iter().any(|operation| {
                        operation.to_string().contains(frame.operation.as_str()) &&
                            !frame.heuristics.contains(&"integer".to_string())
                    })
                })
            {
                spec.arguments.insert(
                    *key,
                    (
                        CalldataFrame {
                            slot: frame.slot,
                            operation: frame.operation.clone(),
                            mask_size: frame.mask_size,
                            heuristics: vec!["integer".to_string()],
                        },
                        potential_types.to_owned(),
                    ),
                );
            }
        } else if ["SHR", "SHL", "SAR", "XOR", "BYTE"].contains(&opcode_name) {
            // get the calldata slot operation
            if let Some((key, (frame, potential_types))) =
                spec.arguments.clone().iter().find(|(_, (frame, _))| {
                    instruction.output_operations.iter().any(|operation| {
                        operation.to_string().contains(frame.operation.as_str()) &&
                            !frame.heuristics.contains(&"bytes".to_string())
                    })
                })
            {
                spec.arguments.insert(
                    *key,
                    (
                        CalldataFrame {
                            slot: frame.slot,
                            operation: frame.operation.clone(),
                            mask_size: frame.mask_size,
                            heuristics: vec!["bytes".to_string()],
                        },
                        potential_types.to_owned(),
                    ),
                );
            }
        }
    }

    if branchSpec.is_revert == None {
        branchSpec.is_revert = Some(false);
    }



    // println!("last instruction: {:?}", last_operation);

    // recurse into the children of the VMTrace map
    for child in vm_trace.children.iter() {
        // println!("child start instruction index: {:?}", child.instruction);
        let mut child_branchSpec = BranchSpec::new();
        (spec, child_branchSpec) = spec_trace(child, spec, child_branchSpec);
        branchSpec.children.push(Box::new(child_branchSpec));
    }



    // // print last operation of vm_trace.operations
    // let last_operation = vm_trace.operations.last().unwrap();
    // let first_operation = vm_trace.operations.first().unwrap();
    // let key = (first_operation.last_instruction.instruction, last_operation.last_instruction.instruction);

    
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

      


    spec.branch_specs.push(branchSpec.clone());

    (spec, branchSpec)
}
