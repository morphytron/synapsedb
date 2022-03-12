pub mod pufms_io {
	use config::{Config, ConfigError};
	use std::collections::HashMap;
	use std::fs::File;
	use std::fs;
	use std::io;
	use std::io::prelude::*;
	use std::io::{BufReader};
	use std::path::Path;

	pub fn read_file(file_name_and_path: &str) -> io::Result<Vec<u8>> {
		let mut buffer = Vec::new();
		let mut _x = &File::open(file_name_and_path)?;
		let mut _reader = BufReader::new(_x);
		_reader.read_to_end(&mut buffer)?;
		Ok(buffer)
	}

	pub fn append_to_file(file_name_and_path: &str, contents : &mut [u8]) -> io::Result<()> {
		let mut file_bytes = read_file(file_name_and_path).unwrap();
		let mut file = File::create(file_name_and_path)?;
		unsafe {
			file_bytes.extend(contents.to_vec());
			file.write_all(file_bytes.as_slice())?;
		}
		Ok(())
	}

	pub fn create_and_write_to_file(file_name_and_path: &str, bytes : &[u8]) -> std::io::Result<()> {
		let mut file = File::create(file_name_and_path)?;
		file.write_all(bytes)?;
		Ok(())
	}

	pub fn test_file_exists(file_name_and_path: &str) -> bool {
		let p = std::path::Path::new(file_name_and_path);
		if p.is_file() {
			true
		}
		else {
			false
		}
	}

	pub fn remove_file(file_name_and_path: &str) -> std::io::Result<()> {
		fs::remove_file(file_name_and_path)?;
		Ok(())
	}
}