use std::{collections::HashMap};

use clap_verbosity_flag::Verbosity;
use heimdall_common::utils::testing::benchmarks;
use heimdall_core::spec::SpecArgs;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::path::{Path, PathBuf};



struct FunctionSpec {
    selector: String,
    signature: String,
    inputs: Vec<String>,
    outputs: Vec<String>,
    state_mutability: String,
    gas: u64,
    constant: bool,
    payable: bool,
}

async fn analyze_one_contract( contract_address: String ) {
    let args = SpecArgs {
        target: String::from(contract_address), // DVM
        verbose: Verbosity::new(0, 0),
        rpc_url: String::from("https://eth.llamarpc.com"),
        default: true,
        skip_resolving: false,
        no_tui: true,
        name: String::from(""),
        output: String::from(""),
        timeout: 10000000,
        selectors_interested: String::from(""),
        initial_storage_values: String::from(""),
    };
    let specs = heimdall_core::spec::spec(args, vec![], HashMap::new()).await.unwrap();

} 


/// Reads each line of a file and stores them in a vector.
///
/// # Arguments
///
/// * `file_path` - A string slice that holds the path of the file to read.
///
/// # Returns
/// A Result containing either a vector of strings (each representing a line of the file) or an io::Error.
async fn read_lines_to_dict(file_path: &str) -> Result<HashMap<String, Vec<String>>, io::Error> {
    let file = File::open(file_path)?;
    let reader = BufReader::new(file);
    let mut benchmarks = HashMap::new();
    let mut current_key = String::new();
    for line_result in reader.lines() {
        let line = line_result?;
        if line.trim().ends_with(':') {
            // New benchmark name found, trim the colon and space
            current_key = line.trim().trim_end_matches(':').to_string();
            benchmarks.entry(current_key.clone()).or_insert_with(Vec::new);
        } else if !line.trim().is_empty() {
            // Line with address, add to the current benchmark's list
            if let Some(addresses) = benchmarks.get_mut(&current_key) {
                addresses.push(line.trim().to_string());
            }
        }
    }
    Ok(benchmarks)
}




#[tokio::main]
async fn main() {
    // read file:
    // Get the compile-time path of the current file (main.rs)
    let current_file_path = file!();
    // Convert it to a Path
    let path = Path::new(current_file_path);
    // Get the directory containing the current file
    let dir = path.parent().expect("Failed to get directory of the current file");
    // Create a PathBuf from the directory and append 'temp.txt' to it
    let mut temp_file_path = PathBuf::from(dir);
    temp_file_path.push("addresses.txt");

    let benchmarks = read_lines_to_dict(temp_file_path.to_str().unwrap()).await.unwrap();

    for (benchmark_name, addresses) in benchmarks.iter() {
        println!("Benchmark: {}", benchmark_name);
        for address in addresses {
            println!("Address: {}", address);
            analyze_one_contract(address.clone()).await;
        }
    }

    // let selector_function_map: HashMap<String, FunctionSpec> = HashMap::new();

    

    // println!("Hello, world!");

}