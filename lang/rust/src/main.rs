use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use std::io::BufReader;

use hex;
use clap::{App, Arg};
use md5::Md5;
use sha1::Sha1;
use sha2::Sha256;
use sha2::Digest;
use sha1::Digest;
use sha256:Digest;
use md5::Digest;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
#[derive(Clone)]
struct FileData {
    file_path: String,
    file_name: String,
    extension: String,
    size: u64,
    mod_time: SystemTime,
    is_dir: bool,
    permissions: u32,
    md5: String,
    sha1: String,
    sha256: String,
}

#[derive(Serialize, Deserialize)]
struct OutputData {
    file_data: Vec<FileData>,
}

fn main() -> io::Result<()> {
    let matches = App::new("File scanning tool")
        .version("1.0")
        .author("OpenAI")
        .about("Traverse directories and gather information on each file")
        .arg(
            Arg::with_name("start-dir")
                .short('s')
                .long("start-dir")
                .value_name("DIR")
                .help("Starting directory for file scanning")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("sub-dirs")
                .short('d')
                .long("sub-dirs")
                .help("Scan subdirectories"),
        )
        .arg(
            Arg::with_name("output")
                .short('o')
                .long("output")
                .value_name("FILE")
                .help("Output file path")
                .takes_value(true),
        )
        .get_matches();

    let start_dir = matches
        .value_of("start-dir")
        .unwrap_or(".")
        .to_string();

    let scan_sub_dirs = matches.is_present("sub-dirs");
    let output_file = matches.value_of("output").unwrap_or("file_data.json");

    let mut files: Vec<PathBuf> = Vec::new();
    let file_data = Arc::new(Mutex::new(Vec::new()));

    traverse_files(&Path::new(&start_dir), &mut files, scan_sub_dirs)?;

    files.par_iter().for_each(|path| {
        if let Ok(data) = process_file(path) {
            let mut file_data = file_data.lock().unwrap();
            file_data.push(data);
        }
    });

    let output_data = OutputData {
        file_data: file_data.lock().unwrap().clone(),
    };

    let json = serde_json::to_string_pretty(&output_data)?;
    fs::write(output_file, json)?;

    println!("Done!");

    Ok(())
}

fn traverse_files(
    dir: &Path,
    files: &mut Vec<PathBuf>,
    scan_sub_dirs: bool,
) -> io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            if scan_sub_dirs {
                traverse_files(&path, files, scan_sub_dirs)?;
            }
        } else {
            files.push(path);
        }
    }
    Ok(())
}

fn process_file(path: &Path) -> io::Result<FileData> {
    let metadata = path.metadata()?;
    let file_name = path.file_name().unwrap().to_str().unwrap().to_string();
    let extension = path.extension().unwrap_or_default().to_str().unwrap().to_string();
    let is_dir = metadata.is_dir();
    #[cfg(unix)]
    let permissions = metadata.permissions().mode();
    #[cfg(not(unix))]
    let permissions = 0;
    
    let size = metadata.len();
    let mod_time = metadata.modified()?;

    let (md5, sha1, sha256) = if !is_dir {
        let file = fs::File::open(&path)?;
        let mut buf_reader = BufReader::new(file);

        let mut md5_context = Md5::default();
        let mut sha1_context = Sha1::default();
        let mut sha256_context = Sha256::default();        

        let mut buffer = [0; 1024];

        loop {
            let read_bytes = buf_reader.read(&mut buffer)?;
            if read_bytes == 0 {
                break;
            }

            md5_context.input(&buffer[..read_bytes]);
            sha1_context.input(&buffer[..read_bytes]);
            sha256_context.input(&buffer[..read_bytes]);            
        }

        let md5 = hex::encode(md5_context.fixed_result());
        let sha1 = hex::encode(sha1_context.fixed_result());
        let sha256 = hex::encode(sha256_context.fixed_result());        

        (md5, sha1, sha256)
    } else {
        (String::new(), String::new(), String::new())
    };

    Ok(FileData {
        file_path: path.to_str().unwrap().to_string(),
        file_name,
        extension,
        size,
        mod_time,
        is_dir,
        permissions,
        md5,
        sha1,
        sha256,
    })
}
