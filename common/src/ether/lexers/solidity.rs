use std::str::FromStr;

use ethers::types::{U256, I256};

use crate::{
    constants::{MEMLEN_REGEX, WORD_REGEX},
    ether::evm::core::opcodes::*,
    utils::strings::encode_hex_reduced,
};

pub fn is_ext_call_precompile(precompile_address: U256) -> bool {
    let address: usize = match precompile_address.try_into() {
        Ok(x) => x,
        Err(_) => usize::MAX,
    };

    matches!(address, 1..=3)
}

impl WrappedOpcode {
    /// Returns a WrappedOpcode's solidity representation.
    pub fn solidify(&self) -> String {
        let simplified_wrapped_opcode = self.simplify();
        if simplified_wrapped_opcode.opcode.name.starts_with("PUSH") {
            return simplified_wrapped_opcode.inputs[0].solidify();
        }
        let wrapped_opcode = simplified_wrapped_opcode.clone();

        let mut solidified_wrapped_opcode = String::new();
        match simplified_wrapped_opcode.opcode.name {
            "ADD" => {
                solidified_wrapped_opcode.push_str(
                    format!("{} + {}", wrapped_opcode.inputs[0].solidify(), wrapped_opcode.inputs[1].solidify())
                        .as_str(),
                );
            }
            "MUL" => {
                solidified_wrapped_opcode.push_str(
                    format!("{} * {}", wrapped_opcode.inputs[0].solidify(), wrapped_opcode.inputs[1].solidify())
                        .as_str(),
                );
            }
            "SUB" => {
                solidified_wrapped_opcode.push_str(
                    format!("{} - {}", wrapped_opcode.inputs[0].solidify(), wrapped_opcode.inputs[1].solidify())
                        .as_str(),
                );
            }
            "DIV" => {
                solidified_wrapped_opcode.push_str(
                    format!("{} / {}", wrapped_opcode.inputs[0].solidify(), wrapped_opcode.inputs[1].solidify())
                        .as_str(),
                );
            }
            "SDIV" => {
                solidified_wrapped_opcode.push_str(
                    format!("{} / {}", wrapped_opcode.inputs[0].solidify(), wrapped_opcode.inputs[1].solidify())
                        .as_str(),
                );
            }
            "MOD" => {
                solidified_wrapped_opcode.push_str(
                    format!("{} % {}", wrapped_opcode.inputs[0].solidify(), wrapped_opcode.inputs[1].solidify())
                        .as_str(),
                );
            }
            "SMOD" => {
                solidified_wrapped_opcode.push_str(
                    format!("{} % {}", wrapped_opcode.inputs[0].solidify(), wrapped_opcode.inputs[1].solidify())
                        .as_str(),
                );
            }
            "ADDMOD" => {
                solidified_wrapped_opcode.push_str(
                    format!(
                        "{} + {} % {}",
                        wrapped_opcode.inputs[0].solidify(),
                        wrapped_opcode.inputs[1].solidify(),
                        wrapped_opcode.inputs[2].solidify()
                    )
                    .as_str(),
                );
            }
            "MULMOD" => {
                solidified_wrapped_opcode.push_str(
                    format!(
                        "({} * {}) % {}",
                        wrapped_opcode.inputs[0].solidify(),
                        wrapped_opcode.inputs[1].solidify(),
                        wrapped_opcode.inputs[2].solidify()
                    )
                    .as_str(),
                );
            }
            "EXP" => {
                solidified_wrapped_opcode.push_str(
                    format!("{} ** {}", wrapped_opcode.inputs[0].solidify(), wrapped_opcode.inputs[1].solidify())
                        .as_str(),
                );
            }
            "LT" => {
                solidified_wrapped_opcode.push_str(
                    format!("{} < {}", wrapped_opcode.inputs[0].solidify(), wrapped_opcode.inputs[1].solidify())
                        .as_str(),
                );
            }
            "GT" => {
                solidified_wrapped_opcode.push_str(
                    format!("{} > {}", wrapped_opcode.inputs[0].solidify(), wrapped_opcode.inputs[1].solidify())
                        .as_str(),
                );
            }
            "SLT" => {
                solidified_wrapped_opcode.push_str(
                    format!("{} < {}", wrapped_opcode.inputs[0].solidify(), wrapped_opcode.inputs[1].solidify())
                        .as_str(),
                );
            }
            "SGT" => {
                solidified_wrapped_opcode.push_str(
                    format!("{} > {}", wrapped_opcode.inputs[0].solidify(), wrapped_opcode.inputs[1].solidify())
                        .as_str(),
                );
            }
            "EQ" => {
                solidified_wrapped_opcode.push_str(
                    format!("{} == {}", wrapped_opcode.inputs[0].solidify(), wrapped_opcode.inputs[1].solidify())
                        .as_str(),
                );
            }
            "ISZERO" => {
                let solidified_input = wrapped_opcode.inputs[0].solidify();

                match solidified_input.contains(' ') {
                    true => {
                        solidified_wrapped_opcode
                            .push_str(format!("!({})", wrapped_opcode.inputs[0].solidify()).as_str());
                    }
                    false => {
                        solidified_wrapped_opcode
                            .push_str(format!("!{}", wrapped_opcode.inputs[0].solidify()).as_str());
                    }
                }
            }
            "AND" => {
                solidified_wrapped_opcode.push_str(
                    format!("({}) & ({})", wrapped_opcode.inputs[0].solidify(), wrapped_opcode.inputs[1].solidify())
                        .as_str(),
                );
            }
            "OR" => {
                solidified_wrapped_opcode.push_str(
                    format!("{} | {}", wrapped_opcode.inputs[0].solidify(), wrapped_opcode.inputs[1].solidify())
                        .as_str(),
                );
            }
            "XOR" => {
                solidified_wrapped_opcode.push_str(
                    format!("{} ^ {}", wrapped_opcode.inputs[0].solidify(), wrapped_opcode.inputs[1].solidify())
                        .as_str(),
                );
            }
            "NOT" => {
                solidified_wrapped_opcode
                    .push_str(format!("~({})", wrapped_opcode.inputs[0].solidify()).as_str());
            }
            "SHL" => {
                solidified_wrapped_opcode.push_str(
                    format!("{} << {}", wrapped_opcode.inputs[1].solidify(), wrapped_opcode.inputs[0].solidify())
                        .as_str(),
                );
            }
            "SHR" => {
                solidified_wrapped_opcode.push_str(
                    format!("{} >> {}", wrapped_opcode.inputs[1].solidify(), wrapped_opcode.inputs[0].solidify())
                        .as_str(),
                );
            }
            "SAR" => {
                solidified_wrapped_opcode.push_str(
                    format!("{} >> {}", wrapped_opcode.inputs[1].solidify(), wrapped_opcode.inputs[0].solidify())
                        .as_str(),
                );
            }
            "BYTE" => {
                solidified_wrapped_opcode.push_str(wrapped_opcode.inputs[1].solidify().as_str());
            }
            "SHA3" => {
                solidified_wrapped_opcode
                    .push_str(&format!("keccak256(memory[{}])", wrapped_opcode.inputs[0].solidify()));
            }
            "ADDRESS" => {
                solidified_wrapped_opcode.push_str("address(this)");
            }
            "BALANCE" => {
                solidified_wrapped_opcode
                    .push_str(format!("address({}).balance", wrapped_opcode.inputs[0].solidify()).as_str());
            }
            "ORIGIN" => {
                solidified_wrapped_opcode.push_str("tx.origin");
            }
            "CALLER" => {
                solidified_wrapped_opcode.push_str("msg.sender");
            }
            "CALLVALUE" => {
                solidified_wrapped_opcode.push_str("msg.value");
            }
            "CALLDATALOAD" => {
                let solidified_slot = wrapped_opcode.inputs[0].solidify();

                // are dealing with a slot that is a constant, we can just use the slot directly
                if WORD_REGEX.is_match(&solidified_slot).unwrap() {
                    // convert to usize
                    match usize::from_str_radix(&solidified_slot.replacen("0x", "", 1), 16) {
                        Ok(slot) => {
                            solidified_wrapped_opcode
                                .push_str(format!("arg{}", (slot - 4) / 32).as_str());
                        }
                        Err(_) => {
                            if solidified_slot.contains("0x04 + ") ||
                                solidified_slot.contains("+ 0x04")
                            {
                                solidified_wrapped_opcode.push_str(
                                    solidified_slot
                                        .replace("0x04 + ", "")
                                        .replace("+ 0x04", "")
                                        .as_str(),
                                );
                            } else {
                                solidified_wrapped_opcode
                                    .push_str(format!("msg.data[{solidified_slot}]").as_str());
                            }
                        }
                    };
                } else {
                    solidified_wrapped_opcode
                        .push_str(format!("msg.data[{solidified_slot}]").as_str());
                }
            }
            "CALLDATASIZE" => {
                solidified_wrapped_opcode.push_str("msg.data.length");
            }
            "CODESIZE" => {
                solidified_wrapped_opcode.push_str("this.code.length");
            }
            "EXTCODESIZE" => {
                solidified_wrapped_opcode.push_str(
                    format!("address({}).code.length", wrapped_opcode.inputs[0].solidify()).as_str(),
                );
            }
            "EXTCODEHASH" => {
                solidified_wrapped_opcode
                    .push_str(format!("address({}).codehash", wrapped_opcode.inputs[0].solidify()).as_str());
            }
            "BLOCKHASH" => {
                solidified_wrapped_opcode
                    .push_str(format!("blockhash({})", wrapped_opcode.inputs[0].solidify()).as_str());
            }
            "COINBASE" => {
                solidified_wrapped_opcode.push_str("block.coinbase");
            }
            "TIMESTAMP" => {
                solidified_wrapped_opcode.push_str("block.timestamp");
            }
            "NUMBER" => {
                solidified_wrapped_opcode.push_str("block.number");
            }
            "DIFFICULTY" => {
                solidified_wrapped_opcode.push_str("block.difficulty");
            }
            "GASLIMIT" => {
                solidified_wrapped_opcode.push_str("block.gaslimit");
            }
            "CHAINID" => {
                solidified_wrapped_opcode.push_str("block.chainid");
            }
            "SELFBALANCE" => {
                solidified_wrapped_opcode.push_str("address(this).balance");
            }
            "BASEFEE" => {
                solidified_wrapped_opcode.push_str("block.basefee");
            }
            "GAS" => {
                solidified_wrapped_opcode.push_str("gasleft()");
            }
            "GASPRICE" => {
                solidified_wrapped_opcode.push_str("tx.gasprice");
            }
            "SLOAD" => {
                solidified_wrapped_opcode
                    .push_str(format!("storage[{}]", wrapped_opcode.inputs[0].solidify()).as_str());
            }
            "MLOAD" => {
                let memloc = wrapped_opcode.inputs[0].solidify();
                if memloc.contains("memory") {
                    match MEMLEN_REGEX.find(&format!("memory[{memloc}]")).unwrap() {
                        Some(_) => {
                            solidified_wrapped_opcode.push_str(format!("{memloc}.length").as_str());
                        }
                        None => {
                            solidified_wrapped_opcode
                                .push_str(format!("memory[{memloc}]").as_str());
                        }
                    }
                } else {
                    solidified_wrapped_opcode.push_str(format!("memory[{memloc}]").as_str());
                }
            }
            "MSIZE" => {
                solidified_wrapped_opcode.push_str("memory.length");
            }
            "CALL" => {
                match U256::from_str(&wrapped_opcode.inputs[1].solidify()) {
                    Ok(addr) => {
                        if is_ext_call_precompile(addr) {
                            solidified_wrapped_opcode
                                .push_str(&format!("memory[{}]", wrapped_opcode.inputs[5].solidify()));
                        } else {
                            solidified_wrapped_opcode.push_str("success");
                        }
                    }
                    Err(_) => {
                        solidified_wrapped_opcode.push_str("success");
                    }
                };
            }
            "CALLCODE" => {
                match U256::from_str(&wrapped_opcode.inputs[1].solidify()) {
                    Ok(addr) => {
                        if is_ext_call_precompile(addr) {
                            solidified_wrapped_opcode
                                .push_str(&format!("memory[{}]", wrapped_opcode.inputs[5].solidify()));
                        } else {
                            solidified_wrapped_opcode.push_str("success");
                        }
                    }
                    Err(_) => {
                        solidified_wrapped_opcode.push_str("success");
                    }
                };
            }
            "DELEGATECALL" => {
                match U256::from_str(&wrapped_opcode.inputs[1].solidify()) {
                    Ok(addr) => {
                        if is_ext_call_precompile(addr) {
                            solidified_wrapped_opcode
                                .push_str(&format!("memory[{}]", wrapped_opcode.inputs[5].solidify()));
                        } else {
                            solidified_wrapped_opcode.push_str("success");
                        }
                    }
                    Err(_) => {
                        solidified_wrapped_opcode.push_str("success");
                    }
                };
            }
            "STATICCALL" => {
                match U256::from_str(&wrapped_opcode.inputs[1].solidify()) {
                    Ok(addr) => {
                        if is_ext_call_precompile(addr) {
                            solidified_wrapped_opcode
                                .push_str(&format!("memory[{}]", wrapped_opcode.inputs[5].solidify()));
                        } else {
                            solidified_wrapped_opcode.push_str("success");
                        }
                    }
                    Err(_) => {
                        solidified_wrapped_opcode.push_str("success");
                    }
                };
            }
            "RETURNDATASIZE" => {
                solidified_wrapped_opcode.push_str("ret0.length");
            }
            "PUSH0" => {
                solidified_wrapped_opcode.push('0');
            }
            opcode => {
                if opcode.starts_with("PUSH") {
                    solidified_wrapped_opcode.push_str(wrapped_opcode.inputs[0].solidify().as_str());
                } else {
                    solidified_wrapped_opcode.push_str(opcode.to_string().as_str());
                }
            }
        }

        solidified_wrapped_opcode
    }

    


    /// creates a new WrappedOpcode from a set of raw inputs
    pub fn new(opcode_int: u8, inputs: Vec<WrappedInput>) -> WrappedOpcode {
        WrappedOpcode { opcode: Opcode::new(opcode_int), inputs }
    }

    /// simplifies a WrappedOpcode
    pub fn simplify(&self) -> WrappedOpcode {
        let mut simplified_wrapped_opcode = WrappedInput::Opcode(self.clone()); 

        simplified_wrapped_opcode.simplify();

        match simplified_wrapped_opcode {
            WrappedInput::Raw( u256 ) => {
                return WrappedOpcode { opcode: Opcode::new(0x60), inputs: vec![WrappedInput::Raw(u256)] }; // Assume a PUSH1 opcode
            }
            WrappedInput::Opcode(wrapped_opcode) => {
                return wrapped_opcode;
            }
        }
    }


}



impl Default for WrappedOpcode {
    fn default() -> Self {
        WrappedOpcode {
            opcode: Opcode { code: 0, name: "unknown", mingas: 0, inputs: 0, outputs: 0 },
            inputs: Vec::new(),
        }
    }
}

impl WrappedInput {
    /// Returns a WrappedInput's solidity representation.
    pub fn solidify(&self) -> String {
        let mut solidified_wrapped_input = String::new();

        match self {
            WrappedInput::Raw(u256) => {
                solidified_wrapped_input.push_str(&encode_hex_reduced(*u256));
            }
            WrappedInput::Opcode(opcode) => {
                let solidified_opcode = opcode.solidify();

                if solidified_opcode.contains(' ') {
                    solidified_wrapped_input.push_str(format!("({solidified_opcode})").as_str());
                } else {
                    solidified_wrapped_input.push_str(solidified_opcode.as_str());
                }
            }
        }

        solidified_wrapped_input
    }

    pub fn simplify(&mut self) {
        match self {
            WrappedInput::Raw(_) => {}
            WrappedInput::Opcode(wrapped_opcode) => {

                for input in wrapped_opcode.inputs.iter_mut() {
                    input.simplify();
                }

                match wrapped_opcode.opcode.name {
                    // "AND" => {
                    //     let first_input = wrapped_opcode.inputs[0].clone();
                    //     let second_input = wrapped_opcode.inputs[1].clone();
                    
                    // }
                    
                    "ADD" => {}

                    // devide by 1 or multiply by 1
                    "DIV" | "MUL" => {
                        // check if self.inputs[1] is WrappedInput::Raw
                        // if so, check if it is 1
                        let first_input: WrappedInput = wrapped_opcode.inputs[1].clone();
                        match first_input {
                            WrappedInput::Raw(u256) if u256 == U256::from(1) => {
                                *self = wrapped_opcode.inputs[0].clone();
                            }
                            _ => {}
                        }
                    }
                    // double negate
                    "ISZERO" => {
                        // check if self.inputs[0] is WrappedInput::Opcode
                        // if so, check if it is ISZERO
                        let second_input = wrapped_opcode.inputs[0].clone();
                        match second_input {
                            WrappedInput::Opcode(wrapped_opcode) => {
                                match wrapped_opcode.opcode.name {
                                    "ISZERO" => {
                                        *self = wrapped_opcode.inputs[0].clone();
                                    }
                                    _ => {}
                                }
                            }
                            _ => {}
                        }
                    }
                    
                    // simplify comparison 
                    // x < 0 => always false
                    // U256::MAX < x => always false
                    "LT" => {
                        let first_input = wrapped_opcode.inputs[0].clone();
                        let second_input = wrapped_opcode.inputs[1].clone();
                        match first_input {
                            WrappedInput::Raw(u256) if u256 == U256::MAX => {
                                *self = WrappedInput::Raw(U256::from(0));
                            }
                            _ => {}
                        }
                        match second_input {
                            WrappedInput::Raw(u256) if u256 == U256::zero() => {
                                *self = WrappedInput::Raw(U256::from(0));
                            }
                            _ => {}
                        }
                    }
                    // x > U256::MAX => always false
                    // 0 > x => always false
                    "GT" => {
                        let first_input = wrapped_opcode.inputs[0].clone();
                        let second_input = wrapped_opcode.inputs[1].clone();
                        // println!("first_input: {:?}", first_input);
                        // println!("second_input: {:?}", second_input);

                        match second_input {
                            WrappedInput::Raw(u256) if u256 == U256::MAX => {
                                *self = WrappedInput::Raw(U256::from(0));
                            }
                            _ => {}
                        }
                        match first_input {
                            WrappedInput::Raw(u256) if u256 == U256::zero() => {
                                *self = WrappedInput::Raw(U256::from(0));
                            }
                            _ => {}
                        }
                    }

                    // x < I256::MIN => always false
                    // I256::MAX < x => always false
                    "SLT" => {
                        let first_input = wrapped_opcode.inputs[0].clone();
                        let second_input = wrapped_opcode.inputs[1].clone();
                        match first_input {
                            WrappedInput::Raw(u256) if I256::from_raw(u256) == I256::MAX => {
                                *self = WrappedInput::Raw(U256::from(0));
                            }
                            _ => {}
                        }
                        match second_input {
                            WrappedInput::Raw(u256) if I256::from_raw(u256) == I256::MIN => {
                                *self = WrappedInput::Raw(U256::from(0));
                            }
                            _ => {}
                        }
                    }

                    // x > I256::MAX => always false
                    // I256::MIN > x => always false
                    "SGT" => {
                        let first_input = wrapped_opcode.inputs[0].clone();
                        let second_input = wrapped_opcode.inputs[1].clone();
                        match second_input {
                            WrappedInput::Raw(u256) if I256::from_raw(u256) == I256::MAX => {
                                *self = WrappedInput::Raw(U256::from(0));
                            }
                            _ => {}
                        }
                        match first_input {
                            WrappedInput::Raw(u256) if I256::from_raw(u256) == I256::MIN => {
                                *self = WrappedInput::Raw(U256::from(0));
                            }
                            _ => {}
                        }
                    }


                    // // convert bitwise operations to a variable type cast
                    // "AND" => {
                    //     let first_input = wrapped_opcode.inputs[0].clone();
                    //     let second_input = wrapped_opcode.inputs[1].clone();


                    // }
                    "PUSH0" => {
                        *self = WrappedInput::Raw(U256::zero());
                    }
                    opcode => {
                        if opcode.starts_with("PUSH") {
                            let pushed = wrapped_opcode.inputs[0].clone();
                            *self = pushed;
                        }

                    }                    
                }
            }
        }



    }
}


// cleanup should be placed here:




#[cfg(test)]
mod tests {
    use crate::ether::{
        evm::core::opcodes::{Opcode, WrappedInput, WrappedOpcode},
        lexers::solidity::is_ext_call_precompile,
    };
    use ethers::types::{U256, I256};

    #[test]
    fn test_is_ext_call_precompile() {
        assert!(is_ext_call_precompile(U256::from(1)));
        assert!(is_ext_call_precompile(U256::from(2)));
        assert!(is_ext_call_precompile(U256::from(3)));
        assert!(!is_ext_call_precompile(U256::from(4)));
        assert!(!is_ext_call_precompile(U256::MAX));
    }

    #[test]
    fn test_wrapped_opcodesolidify_add() {
        let opcode = Opcode { code: 0x01, name: "ADD", mingas: 1, inputs: 2, outputs: 1 };
        let inputs = vec![WrappedInput::Raw(U256::from(1u8)), WrappedInput::Raw(U256::from(2u8))];
        let wrapped_opcode = WrappedOpcode { opcode, inputs };

        assert_eq!(wrapped_opcode.solidify(), "0x01 + 0x02");
    }

    #[test]
    fn test_wrapped_opcodesolidify_mul() {
        let opcode = Opcode { code: 0x02, name: "MUL", mingas: 1, inputs: 2, outputs: 1 };
        let inputs = vec![WrappedInput::Raw(U256::from(2u8)), WrappedInput::Raw(U256::from(3u8))];
        let wrapped_opcode = WrappedOpcode { opcode, inputs };

        assert_eq!(wrapped_opcode.solidify(), "0x02 * 0x03");
    }

    #[test]
    fn test_wrapped_opcodesolidify_sub() {
        let opcode = Opcode { code: 0x03, name: "SUB", mingas: 1, inputs: 2, outputs: 1 };
        let inputs = vec![WrappedInput::Raw(U256::from(5u8)), WrappedInput::Raw(U256::from(3u8))];
        let wrapped_opcode = WrappedOpcode { opcode, inputs };

        assert_eq!(wrapped_opcode.solidify(), "0x05 - 0x03");
    }

    #[test]
    fn test_wrapped_opcodesolidify_div() {
        let opcode = Opcode { code: 0x04, name: "DIV", mingas: 1, inputs: 2, outputs: 1 };
        let inputs = vec![WrappedInput::Raw(U256::from(10u8)), WrappedInput::Raw(U256::from(2u8))];
        let wrapped_opcode = WrappedOpcode { opcode, inputs };

        assert_eq!(wrapped_opcode.solidify(), "0x0a / 0x02");
    }

    #[test]
    fn test_wrapped_opcodesolidify_sdiv() {
        let opcode = Opcode { code: 0x05, name: "SDIV", mingas: 1, inputs: 2, outputs: 1 };
        let inputs = vec![WrappedInput::Raw(U256::from(10u8)), WrappedInput::Raw(U256::from(2u8))];
        let wrapped_opcode = WrappedOpcode { opcode, inputs };

        assert_eq!(wrapped_opcode.solidify(), "0x0a / 0x02");
    }

    #[test]
    fn test_wrapped_opcodesolidify_mod() {
        let opcode = Opcode { code: 0x06, name: "MOD", mingas: 1, inputs: 2, outputs: 1 };
        let inputs = vec![WrappedInput::Raw(U256::from(10u8)), WrappedInput::Raw(U256::from(3u8))];
        let wrapped_opcode = WrappedOpcode { opcode, inputs };

        assert_eq!(wrapped_opcode.solidify(), "0x0a % 0x03");
    }

    #[test]
    fn test_wrapped_opcodesolidify_smod() {
        let opcode = Opcode { code: 0x07, name: "SMOD", mingas: 1, inputs: 2, outputs: 1 };
        let inputs = vec![WrappedInput::Raw(U256::from(10u8)), WrappedInput::Raw(U256::from(3u8))];
        let wrapped_opcode = WrappedOpcode { opcode, inputs };

        assert_eq!(wrapped_opcode.solidify(), "0x0a % 0x03");
    }

    #[test]
    fn test_wrapped_opcodesolidify_addmod() {
        let opcode = Opcode { code: 0x08, name: "ADDMOD", mingas: 1, inputs: 3, outputs: 1 };
        let inputs = vec![
            WrappedInput::Raw(U256::from(3u8)),
            WrappedInput::Raw(U256::from(4u8)),
            WrappedInput::Raw(U256::from(5u8)),
        ];
        let wrapped_opcode = WrappedOpcode { opcode, inputs };

        assert_eq!(wrapped_opcode.solidify(), "0x03 + 0x04 % 0x05");
    }

    #[test]
    fn test_wrapped_opcodesolidify_mulmod() {
        let opcode = Opcode { code: 0x09, name: "MULMOD", mingas: 1, inputs: 3, outputs: 1 };
        let inputs = vec![
            WrappedInput::Raw(U256::from(3u8)),
            WrappedInput::Raw(U256::from(4u8)),
            WrappedInput::Raw(U256::from(5u8)),
        ];
        let wrapped_opcode = WrappedOpcode { opcode, inputs };

        assert_eq!(wrapped_opcode.solidify(), "(0x03 * 0x04) % 0x05");
    }

    #[test]
    fn test_wrapped_opcodesolidify_exp() {
        let opcode = Opcode { code: 0x0a, name: "EXP", mingas: 1, inputs: 2, outputs: 1 };
        let inputs = vec![WrappedInput::Raw(U256::from(2u8)), WrappedInput::Raw(U256::from(3u8))];
        let wrapped_opcode = WrappedOpcode { opcode, inputs };

        assert_eq!(wrapped_opcode.solidify(), "0x02 ** 0x03");
    }

    #[test]
    fn test_wrapped_opcodesolidify_lt() {
        let opcode = Opcode { code: 0x10, name: "LT", mingas: 1, inputs: 2, outputs: 1 };
        let inputs = vec![WrappedInput::Raw(U256::from(2u8)), WrappedInput::Raw(U256::from(3u8))];
        let wrapped_opcode = WrappedOpcode { opcode, inputs };

        assert_eq!(wrapped_opcode.solidify(), "0x02 < 0x03");
    }

    #[test]
    fn test_wrapped_opcodesolidify_gt() {
        let opcode = Opcode { code: 0x11, name: "GT", mingas: 1, inputs: 2, outputs: 1 };
        let inputs = vec![WrappedInput::Raw(U256::from(5u8)), WrappedInput::Raw(U256::from(3u8))];
        let wrapped_opcode = WrappedOpcode { opcode, inputs };

        assert_eq!(wrapped_opcode.solidify(), "0x05 > 0x03");
    }

    #[test]
    fn test_wrapped_opcodesolidify_slt() {
        let opcode = Opcode { code: 0x12, name: "SLT", mingas: 1, inputs: 2, outputs: 1 };
        let inputs = vec![WrappedInput::Raw(U256::from(2u8)), WrappedInput::Raw(U256::from(3u8))];
        let wrapped_opcode = WrappedOpcode { opcode, inputs };

        assert_eq!(wrapped_opcode.solidify(), "0x02 < 0x03");
    }

    #[test]
    fn test_wrapped_opcodesolidify_sgt() {
        let opcode = Opcode { code: 0x13, name: "SGT", mingas: 1, inputs: 2, outputs: 1 };
        let inputs = vec![WrappedInput::Raw(U256::from(5u8)), WrappedInput::Raw(U256::from(3u8))];
        let wrapped_opcode = WrappedOpcode { opcode, inputs };

        assert_eq!(wrapped_opcode.solidify(), "0x05 > 0x03");
    }

    #[test]
    fn test_wrapped_opcodesolidify_eq() {
        let opcode = Opcode { code: 0x14, name: "EQ", mingas: 1, inputs: 2, outputs: 1 };
        let inputs = vec![WrappedInput::Raw(U256::from(5u8)), WrappedInput::Raw(U256::from(5u8))];
        let wrapped_opcode = WrappedOpcode { opcode, inputs };

        assert_eq!(wrapped_opcode.solidify(), "0x05 == 0x05");
    }

    #[test]
    fn test_wrapped_opcodesolidify_iszero() {
        let opcode = Opcode { code: 0x15, name: "ISZERO", mingas: 1, inputs: 1, outputs: 1 };
        let inputs = vec![WrappedInput::Raw(U256::from(0u8))];
        let wrapped_opcode = WrappedOpcode { opcode, inputs };

        assert_eq!(wrapped_opcode.solidify(), "!0");
    }

    #[test]
    fn test_wrapped_opcodesolidify_and() {
        let opcode = Opcode { code: 0x16, name: "AND", mingas: 1, inputs: 2, outputs: 1 };
        let inputs =
            vec![WrappedInput::Raw(U256::from(0b1010u8)), WrappedInput::Raw(U256::from(0b1100u8))];
        let wrapped_opcode = WrappedOpcode { opcode, inputs };

        assert_eq!(wrapped_opcode.solidify(), "(0x0a) & (0x0c)");
    }

    #[test]
    fn test_wrapped_opcodesolidify_or() {
        let opcode = Opcode { code: 0x17, name: "OR", mingas: 1, inputs: 2, outputs: 1 };
        let inputs =
            vec![WrappedInput::Raw(U256::from(0b1010u8)), WrappedInput::Raw(U256::from(0b1100u8))];
        let wrapped_opcode = WrappedOpcode { opcode, inputs };

        assert_eq!(wrapped_opcode.solidify(), "0x0a | 0x0c");
    }

    #[test]
    fn test_wrapped_opcodesolidify_xor() {
        let opcode = Opcode { code: 0x18, name: "XOR", mingas: 1, inputs: 2, outputs: 1 };
        let inputs =
            vec![WrappedInput::Raw(U256::from(0b1010u8)), WrappedInput::Raw(U256::from(0b1100u8))];
        let wrapped_opcode = WrappedOpcode { opcode, inputs };

        assert_eq!(wrapped_opcode.solidify(), "0x0a ^ 0x0c");
    }

    #[test]
    fn test_wrapped_opcodesolidify_not() {
        let opcode = Opcode { code: 0x19, name: "NOT", mingas: 1, inputs: 1, outputs: 1 };
        let inputs = vec![WrappedInput::Raw(U256::from(0b1010u8))];
        let wrapped_opcode = WrappedOpcode { opcode, inputs };

        assert_eq!(wrapped_opcode.solidify(), "~(0x0a)");
    }

    #[test]
    fn test_wrapped_opcodesolidify_shl() {
        let opcode = Opcode { code: 0x1a, name: "SHL", mingas: 1, inputs: 2, outputs: 1 };
        let inputs = vec![WrappedInput::Raw(U256::from(3u8)), WrappedInput::Raw(U256::from(1u8))];
        let wrapped_opcode = WrappedOpcode { opcode, inputs };

        assert_eq!(wrapped_opcode.solidify(), "0x01 << 0x03");
    }

    #[test]
    fn test_wrapped_opcodesolidify_shr() {
        let opcode = Opcode { code: 0x1b, name: "SHR", mingas: 1, inputs: 2, outputs: 1 };
        let inputs = vec![WrappedInput::Raw(U256::from(6u8)), WrappedInput::Raw(U256::from(1u8))];
        let wrapped_opcode = WrappedOpcode { opcode, inputs };

        assert_eq!(wrapped_opcode.solidify(), "0x01 >> 0x06");
    }

    #[test]
    fn test_wrapped_opcodesolidify_sar() {
        let opcode = Opcode { code: 0x1c, name: "SAR", mingas: 1, inputs: 2, outputs: 1 };
        let inputs = vec![WrappedInput::Raw(U256::from(6u8)), WrappedInput::Raw(U256::from(1u8))];
        let wrapped_opcode = WrappedOpcode { opcode, inputs };

        assert_eq!(wrapped_opcode.solidify(), "0x01 >> 0x06");
    }

    #[test]
    fn test_wrapped_opcodesolidify_byte() {
        let opcode = Opcode { code: 0x1d, name: "BYTE", mingas: 1, inputs: 2, outputs: 1 };
        let inputs =
            vec![WrappedInput::Raw(U256::from(3u8)), WrappedInput::Raw(U256::from(0x12345678u32))];
        let wrapped_opcode = WrappedOpcode { opcode, inputs };

        assert_eq!(wrapped_opcode.solidify(), "0x12345678");
    }

    #[test]
    fn test_wrapped_opcodesolidify_sha3() {
        let opcode = Opcode { code: 0x20, name: "SHA3", mingas: 1, inputs: 1, outputs: 1 };
        let inputs = vec![WrappedInput::Raw(U256::from(0u8))];
        let wrapped_opcode = WrappedOpcode { opcode, inputs };

        assert_eq!(wrapped_opcode.solidify(), "keccak256(memory[0])");
    }

    #[test]
    fn test_wrapped_opcodesolidify_address() {
        let opcode = Opcode { code: 0x30, name: "ADDRESS", mingas: 1, inputs: 0, outputs: 1 };
        let inputs = vec![];
        let wrapped_opcode = WrappedOpcode { opcode, inputs };

        assert_eq!(wrapped_opcode.solidify(), "address(this)");
    }

    #[test]
    fn test_wrapped_opcodesolidify_balance() {
        let opcode = Opcode { code: 0x31, name: "BALANCE", mingas: 1, inputs: 1, outputs: 1 };
        let inputs = vec![WrappedInput::Raw(U256::from(0x1234u16))];
        let wrapped_opcode = WrappedOpcode { opcode, inputs };

        assert_eq!(wrapped_opcode.solidify(), "address(0x1234).balance");
    }

    #[test]
    fn test_wrapped_opcodesolidify_origin() {
        let opcode = Opcode { code: 0x32, name: "ORIGIN", mingas: 1, inputs: 0, outputs: 1 };
        let inputs = vec![];
        let wrapped_opcode = WrappedOpcode { opcode, inputs };

        assert_eq!(wrapped_opcode.solidify(), "tx.origin");
    }

    #[test]
    fn test_wrapped_opcodesolidify_caller() {
        let opcode = Opcode { code: 0x33, name: "CALLER", mingas: 1, inputs: 0, outputs: 1 };
        let inputs = vec![];
        let wrapped_opcode = WrappedOpcode { opcode, inputs };

        assert_eq!(wrapped_opcode.solidify(), "msg.sender");
    }

    #[test]
    fn test_wrapped_opcodesolidify_callvalue() {
        let opcode = Opcode { code: 0x34, name: "CALLVALUE", mingas: 1, inputs: 0, outputs: 1 };
        let inputs = vec![];
        let wrapped_opcode = WrappedOpcode { opcode, inputs };

        assert_eq!(wrapped_opcode.solidify(), "msg.value");
    }

    #[test]
    fn test_wrapped_opcodesolidify_calldataload() {
        let opcode = Opcode { code: 0x35, name: "CALLDATALOAD", mingas: 1, inputs: 1, outputs: 1 };
        let inputs = vec![WrappedInput::Raw(U256::from(0x1234u16))];
        let wrapped_opcode = WrappedOpcode { opcode, inputs };

        assert_eq!(wrapped_opcode.solidify(), "arg145");
    }

    #[test]
    fn test_wrapped_opcodesolidify_calldatasize() {
        let opcode = Opcode { code: 0x36, name: "CALLDATASIZE", mingas: 1, inputs: 0, outputs: 1 };
        let inputs = vec![];
        let wrapped_opcode = WrappedOpcode { opcode, inputs };

        assert_eq!(wrapped_opcode.solidify(), "msg.data.length");
    }

    #[test]
    fn test_wrapped_opcodesolidify_codesize() {
        let opcode = Opcode { code: 0x38, name: "CODESIZE", mingas: 1, inputs: 0, outputs: 1 };
        let inputs = vec![];
        let wrapped_opcode = WrappedOpcode { opcode, inputs };

        assert_eq!(wrapped_opcode.solidify(), "this.code.length");
    }

    #[test]
    fn test_wrapped_opcodesolidify_extcodesize() {
        let opcode = Opcode { code: 0x3b, name: "EXTCODESIZE", mingas: 1, inputs: 1, outputs: 1 };
        let inputs = vec![WrappedInput::Raw(U256::from(0x1234u16))];
        let wrapped_opcode = WrappedOpcode { opcode, inputs };

        assert_eq!(wrapped_opcode.solidify(), "address(0x1234).code.length");
    }

    #[test]
    fn test_wrapped_opcodesolidify_extcodehash() {
        let opcode = Opcode { code: 0x3f, name: "EXTCODEHASH", mingas: 1, inputs: 1, outputs: 1 };
        let inputs = vec![WrappedInput::Raw(U256::from(0x1234u16))];
        let wrapped_opcode = WrappedOpcode { opcode, inputs };

        assert_eq!(wrapped_opcode.solidify(), "address(0x1234).codehash");
    }

    #[test]
    fn test_wrapped_opcodesolidify_blockhash() {
        let opcode = Opcode { code: 0x40, name: "BLOCKHASH", mingas: 1, inputs: 1, outputs: 1 };
        let inputs = vec![WrappedInput::Raw(U256::from(0x1234u16))];
        let wrapped_opcode = WrappedOpcode { opcode, inputs };

        assert_eq!(wrapped_opcode.solidify(), "blockhash(0x1234)");
    }

    #[test]
    fn test_wrapped_opcodesolidify_coinbase() {
        let opcode = Opcode { code: 0x41, name: "COINBASE", mingas: 1, inputs: 0, outputs: 1 };
        let inputs = vec![];
        let wrapped_opcode = WrappedOpcode { opcode, inputs };

        assert_eq!(wrapped_opcode.solidify(), "block.coinbase");
    }

    #[test]
    fn test_wrapped_opcodesolidify_timestamp() {
        let opcode = Opcode { code: 0x42, name: "TIMESTAMP", mingas: 1, inputs: 0, outputs: 1 };
        let inputs = vec![];
        let wrapped_opcode = WrappedOpcode { opcode, inputs };

        assert_eq!(wrapped_opcode.solidify(), "block.timestamp");
    }

    #[test]
    fn test_wrapped_opcodesolidify_number() {
        let opcode = Opcode { code: 0x43, name: "NUMBER", mingas: 1, inputs: 0, outputs: 1 };
        let inputs = vec![];
        let wrapped_opcode = WrappedOpcode { opcode, inputs };

        assert_eq!(wrapped_opcode.solidify(), "block.number");
    }

    #[test]
    fn test_wrapped_opcodesolidify_difficulty() {
        let opcode = Opcode { code: 0x44, name: "DIFFICULTY", mingas: 1, inputs: 0, outputs: 1 };
        let inputs = vec![];
        let wrapped_opcode = WrappedOpcode { opcode, inputs };

        assert_eq!(wrapped_opcode.solidify(), "block.difficulty");
    }

    #[test]
    fn test_wrapped_opcodesolidify_gaslimit() {
        let opcode = Opcode { code: 0x45, name: "GASLIMIT", mingas: 1, inputs: 0, outputs: 1 };
        let inputs = vec![];
        let wrapped_opcode = WrappedOpcode { opcode, inputs };

        assert_eq!(wrapped_opcode.solidify(), "block.gaslimit");
    }

    #[test]
    fn test_wrapped_opcodesolidify_chainid() {
        let opcode = Opcode { code: 0x46, name: "CHAINID", mingas: 1, inputs: 0, outputs: 1 };
        let inputs = vec![];
        let wrapped_opcode = WrappedOpcode { opcode, inputs };

        assert_eq!(wrapped_opcode.solidify(), "block.chainid");
    }

    #[test]
    fn test_wrapped_opcodesolidify_selfbalance() {
        let opcode = Opcode { code: 0x47, name: "SELFBALANCE", mingas: 1, inputs: 0, outputs: 1 };
        let inputs = vec![];
        let wrapped_opcode = WrappedOpcode { opcode, inputs };

        assert_eq!(wrapped_opcode.solidify(), "address(this).balance");
    }

    #[test]
    fn test_wrapped_opcodesolidify_basefee() {
        let opcode = Opcode { code: 0x48, name: "BASEFEE", mingas: 1, inputs: 0, outputs: 1 };
        let inputs = vec![];
        let wrapped_opcode = WrappedOpcode { opcode, inputs };

        assert_eq!(wrapped_opcode.solidify(), "block.basefee");
    }

    #[test]
    fn test_wrapped_opcodesolidify_gas() {
        let opcode = Opcode { code: 0x5a, name: "GAS", mingas: 1, inputs: 0, outputs: 1 };
        let inputs = vec![];
        let wrapped_opcode = WrappedOpcode { opcode, inputs };

        assert_eq!(wrapped_opcode.solidify(), "gasleft()");
    }

    #[test]
    fn test_wrapped_opcodesolidify_gasprice() {
        let opcode = Opcode { code: 0x3a, name: "GASPRICE", mingas: 1, inputs: 0, outputs: 1 };
        let inputs = vec![];
        let wrapped_opcode = WrappedOpcode { opcode, inputs };

        assert_eq!(wrapped_opcode.solidify(), "tx.gasprice");
    }

    #[test]
    fn test_wrapped_opcodesolidify_sload() {
        let opcode = Opcode { code: 0x54, name: "SLOAD", mingas: 1, inputs: 1, outputs: 1 };
        let inputs = vec![WrappedInput::Raw(U256::from(0x1234u16))];
        let wrapped_opcode = WrappedOpcode { opcode, inputs };

        assert_eq!(wrapped_opcode.solidify(), "storage[0x1234]");
    }

    #[test]
    fn test_wrapped_opcodesolidify_mload() {
        let opcode = Opcode { code: 0x51, name: "MLOAD", mingas: 1, inputs: 1, outputs: 1 };
        let inputs = vec![WrappedInput::Raw(U256::from(0x1234u16))];
        let wrapped_opcode = WrappedOpcode { opcode, inputs };

        assert_eq!(wrapped_opcode.solidify(), "memory[0x1234]");
    }

    #[test]
    fn test_wrapped_opcodesolidify_msize() {
        let opcode = Opcode { code: 0x59, name: "MSIZE", mingas: 1, inputs: 0, outputs: 1 };
        let inputs = vec![];
        let wrapped_opcode = WrappedOpcode { opcode, inputs };

        assert_eq!(wrapped_opcode.solidify(), "memory.length");
    }

    #[test]
    fn test_wrapped_opcodesolidify_call() {
        let opcode = Opcode { code: 0xf1, name: "CALL", mingas: 1, inputs: 7, outputs: 1 };
        let inputs = vec![
            WrappedInput::Raw(U256::from(0x1234u16)),
            WrappedInput::Raw(U256::from(0x01u8)),
            WrappedInput::Raw(U256::from(0x02u8)),
            WrappedInput::Raw(U256::from(0x03u8)),
            WrappedInput::Raw(U256::from(0x04u8)),
            WrappedInput::Raw(U256::from(0x05u8)),
            WrappedInput::Raw(U256::from(0x06u8)),
        ];
        let wrapped_opcode = WrappedOpcode { opcode, inputs };

        assert_eq!(wrapped_opcode.solidify(), "memory[0x05]");
    }

    #[test]
    fn test_wrapped_opcodesolidify_callcode() {
        let opcode = Opcode { code: 0xf2, name: "CALLCODE", mingas: 1, inputs: 7, outputs: 1 };
        let inputs = vec![
            WrappedInput::Raw(U256::from(0x1234u16)),
            WrappedInput::Raw(U256::from(0x01u8)),
            WrappedInput::Raw(U256::from(0x02u8)),
            WrappedInput::Raw(U256::from(0x03u8)),
            WrappedInput::Raw(U256::from(0x04u8)),
            WrappedInput::Raw(U256::from(0x05u8)),
            WrappedInput::Raw(U256::from(0x06u8)),
        ];
        let wrapped_opcode = WrappedOpcode { opcode, inputs };

        assert_eq!(wrapped_opcode.solidify(), "memory[0x05]");
    }

    #[test]
    fn test_wrapped_opcodesolidify_delegatecall() {
        let opcode = Opcode { code: 0xf4, name: "DELEGATECALL", mingas: 1, inputs: 6, outputs: 1 };
        let inputs = vec![
            WrappedInput::Raw(U256::from(0x1234u16)),
            WrappedInput::Raw(U256::from(0x01u8)),
            WrappedInput::Raw(U256::from(0x02u8)),
            WrappedInput::Raw(U256::from(0x03u8)),
            WrappedInput::Raw(U256::from(0x04u8)),
            WrappedInput::Raw(U256::from(0x05u8)),
        ];
        let wrapped_opcode = WrappedOpcode { opcode, inputs };

        assert_eq!(wrapped_opcode.solidify(), "memory[0x05]");
    }

    #[test]
    fn test_wrapped_opcodesolidify_staticcall() {
        let opcode = Opcode { code: 0xfa, name: "STATICCALL", mingas: 1, inputs: 6, outputs: 1 };
        let inputs = vec![
            WrappedInput::Raw(U256::from(0x1234u16)),
            WrappedInput::Raw(U256::from(0x01u8)),
            WrappedInput::Raw(U256::from(0x02u8)),
            WrappedInput::Raw(U256::from(0x03u8)),
            WrappedInput::Raw(U256::from(0x04u8)),
            WrappedInput::Raw(U256::from(0x05u8)),
        ];
        let wrapped_opcode = WrappedOpcode { opcode, inputs };

        assert_eq!(wrapped_opcode.solidify(), "memory[0x05]");
    }

    #[test]
    fn test_wrapped_opcodesolidify_returndatasize() {
        let opcode =
            Opcode { code: 0x3d, name: "RETURNDATASIZE", mingas: 1, inputs: 0, outputs: 1 };
        let inputs = vec![];
        let wrapped_opcode = WrappedOpcode { opcode, inputs };

        assert_eq!(wrapped_opcode.solidify(), "ret0.length");
    }

    #[test]
    fn test_wrapped_opcodesolidify_push() {
        let opcode = Opcode { code: 0x5f, name: "PUSH0", mingas: 1, inputs: 0, outputs: 1 };
        let inputs = vec![];
        let wrapped_opcode = WrappedOpcode { opcode, inputs };

        assert_eq!(wrapped_opcode.solidify(), "0");
    }

    #[test]
    fn test_wrapped_opcodesolidify_unknown() {
        let opcode = Opcode { code: 0xff, name: "unknown", mingas: 1, inputs: 0, outputs: 0 };
        let inputs = vec![];
        let wrapped_opcode = WrappedOpcode { opcode, inputs };

        assert_eq!(wrapped_opcode.solidify(), "unknown");
    }


    #[test]
    fn test_wrapped_opcode_simplify_div_by_1() {
        let opcode = Opcode { code: 0x04, name: "DIV", mingas: 1, inputs: 2, outputs: 1 };
        let inputs = vec![WrappedInput::Raw(U256::from(10u8)), WrappedInput::Raw(U256::from(1u8))];
        let wrapped_opcode = WrappedOpcode { opcode, inputs };

        // println!("before simplification: {}", wrapped_opcode.solidify());
        let simplified = wrapped_opcode.simplify();

        // println!("after simplification: {}", simplified.solidify());
        assert_eq!(simplified.solidify(), "0x0a");
    }


    #[test]
    fn test_wrapped_opcode_simplify_mul_by_1() {
        let opcode = Opcode { code: 0x04, name: "MUL", mingas: 1, inputs: 2, outputs: 1 };
        let inputs = vec![WrappedInput::Raw(U256::from(10u8)), WrappedInput::Raw(U256::from(1u8))];
        let wrapped_opcode = WrappedOpcode { opcode, inputs };

        // println!("before simplification: {}", wrapped_opcode.solidify());
        let simplified = wrapped_opcode.simplify();

        // println!("after simplification: {}", simplified.solidify());
        assert_eq!(simplified.solidify(), "0x0a");
    }


    #[test]
    fn test_wrapped_opcode_double_negate() {
        let opcode = Opcode { code: 0x15, name: "ISZERO", mingas: 1, inputs: 1, outputs: 1 };
        let inputs = vec![WrappedInput::Opcode(WrappedOpcode::new(0x15, vec![WrappedInput::Opcode(WrappedOpcode::new(0x15, vec![WrappedInput::Raw(U256::from(0u8))]))]))];
        let wrapped_opcode = WrappedOpcode { opcode, inputs };

        println!("before simplification: {}", wrapped_opcode.solidify()); // !!!0
        let simplified = wrapped_opcode.simplify();

    
        println!("after simplification: {}", simplified.solidify()); // !0
        assert_eq!(simplified.solidify(), "!0");
    }


    #[test]
    fn test_wrapped_opcode_simplify_comparison() {

        // case 1: x < 0 => always false
        let opcode1 = Opcode { code: 0x10, name: "LT", mingas: 1, inputs: 2, outputs: 1 };
        let inputs1 = vec![WrappedInput::Raw(U256::from(12345u64)), WrappedInput::Raw(U256::from(0u8))];
        let wrapped_opcode1 = WrappedOpcode { opcode: opcode1, inputs: inputs1 };
        println!("before simplification: {}", wrapped_opcode1.solidify()); // 0 < 0
        let simplified1 = wrapped_opcode1.simplify();
        println!("after simplification: {}", simplified1.solidify()); // false
        // assert_eq!(simplified1.solidify(), "0x00");


        // case 2: U256::MAX < x => always false
        let opcode2 = Opcode { code: 0x10, name: "LT", mingas: 1, inputs: 2, outputs: 1 };
        let inputs2 = vec![WrappedInput::Raw(U256::MAX), WrappedInput::Raw(U256::from(12345u64))];
        let wrapped_opcode2 = WrappedOpcode { opcode: opcode2, inputs: inputs2 };
        println!("before simplification: {}", wrapped_opcode2.solidify()); // 0 < 0
        let simplified2 = wrapped_opcode2.simplify();
        println!("after simplification: {}", simplified2.solidify()); // false
        // assert_eq!(simplified2.solidify(), "0x00");


        // case 3: x > U256::MAX => always false
        let opcode3 = Opcode { code: 0x11, name: "GT", mingas: 1, inputs: 2, outputs: 1 };
        let inputs3 = vec![WrappedInput::Raw(U256::from(12345u64)), WrappedInput::Raw(U256::MAX)];
        let wrapped_opcode3 = WrappedOpcode { opcode: opcode3, inputs: inputs3 };
        println!("before simplification: {}", wrapped_opcode3.solidify()); // 0 < 0
        let simplified3 = wrapped_opcode3.simplify();
        println!("after simplification: {}", simplified3.solidify()); // false
        // assert_eq!(simplified3.solidify(), "0x00");

        // case 4: 0 > x => always false
        let opcode4 = Opcode { code: 0x11, name: "GT", mingas: 1, inputs: 2, outputs: 1 };
        let inputs4 = vec![WrappedInput::Raw(U256::from(0u8)), WrappedInput::Raw(U256::from(12345u64))];
        let wrapped_opcode4 = WrappedOpcode { opcode: opcode4, inputs: inputs4 };
        println!("before simplification: {}", wrapped_opcode4.solidify()); // 0 < 0
        let simplified4 = wrapped_opcode4.simplify();
        println!("after simplification: {}", simplified4.solidify()); // false
        // assert_eq!(simplified4.solidify(), "0x00");

        // case 5: x < I256::MIN => always false
        let opcode5 = Opcode { code: 0x10, name: "SLT", mingas: 1, inputs: 2, outputs: 1 };
        let inputs5 = vec![WrappedInput::Raw(U256::from(12345u64)), WrappedInput::Raw( I256::MIN.into_raw() )];
        let wrapped_opcode5 = WrappedOpcode { opcode: opcode5, inputs: inputs5 };
        println!("before simplification: {}", wrapped_opcode5.solidify()); // 0 < 0
        let simplified5 = wrapped_opcode5.simplify();
        println!("after simplification: {}", simplified5.solidify()); // false
        // assert_eq!(simplified5.solidify(), "0x00");

        // case 6: I256::MAX < x => always false
        let opcode6 = Opcode { code: 0x10, name: "SLT", mingas: 1, inputs: 2, outputs: 1 };
        let inputs6 = vec![WrappedInput::Raw( I256::MAX.into_raw() ), WrappedInput::Raw(U256::from(12345u64))];
        let wrapped_opcode6 = WrappedOpcode { opcode: opcode6, inputs: inputs6 };
        println!("before simplification: {}", wrapped_opcode6.solidify()); // 0 < 0
        let simplified6 = wrapped_opcode6.simplify();
        println!("after simplification: {}", simplified6.solidify()); // false
        // assert_eq!(simplified6.solidify(), "0x00");

        // case 7: x > I256::MAX => always false
        let opcode7 = Opcode { code: 0x11, name: "SGT", mingas: 1, inputs: 2, outputs: 1 };
        let inputs7 = vec![WrappedInput::Raw(U256::from(12345u64)), WrappedInput::Raw( I256::MAX.into_raw() )];
        let wrapped_opcode7 = WrappedOpcode { opcode: opcode7, inputs: inputs7 };
        println!("before simplification: {}", wrapped_opcode7.solidify()); // 0 < 0
        let simplified7 = wrapped_opcode7.simplify();
        println!("after simplification: {}", simplified7.solidify()); // false
        // assert_eq!(simplified7.solidify(), "0x00");

        // case 8: I256::MIN > x => always false
        let opcode8 = Opcode { code: 0x11, name: "SGT", mingas: 1, inputs: 2, outputs: 1 };
        let inputs8 = vec![WrappedInput::Raw( I256::MIN.into_raw() ), WrappedInput::Raw(U256::from(12345u64))];
        let wrapped_opcode8 = WrappedOpcode { opcode: opcode8, inputs: inputs8 };
        println!("before simplification: {}", wrapped_opcode8.solidify()); // 0 < 0
        let simplified8 = wrapped_opcode8.simplify();
        println!("after simplification: {}", simplified8.solidify()); // false
        // assert_eq!(simplified8.solidify(), "0x00");


        

    }


}
