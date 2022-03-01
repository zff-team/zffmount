// - modules
pub mod constants;

// - STD
use std::fs::{File};
use std::io::{Read, Seek};
use std::process::exit;

// - internal
use super::Cli;
use zff::{
	Result,
	HeaderCoding,
	header::{MainHeader, SegmentHeader},
	constants::*,
};
use constants::*;

pub enum HeaderType {
	MainHeader(MainHeader),
	SegmentHeader(SegmentHeader),
}

pub fn get_header_type(inputfile: &mut File,  args: &Cli) -> Result<HeaderType> {
    //read header signature and version
    let mut header_signature = [0u8; HEADER_SIGNATURE_LENGTH];
    let mut header_length = [0u8; HEADER_LENGTH_LENGTH];
    let mut header_version = [0u8; HEADER_VERSION_LENGTH];
    inputfile.read_exact(&mut header_signature)?;
    inputfile.read_exact(&mut header_length)?;
    inputfile.read_exact(&mut header_version)?;
    inputfile.rewind()?;

    match u32::from_be_bytes(header_signature) {
        HEADER_IDENTIFIER_MAIN_HEADER => main_header(inputfile, u8::from_be_bytes(header_version)),
        HEADER_IDENTIFIER_SEGMENT_HEADER => return segment_header(inputfile, u8::from_be_bytes(header_version)),
        _ => {
            eprintln!("{ERROR_UNKNOWN_HEADER}");
            exit(EXIT_STATUS_ERROR);
        }
    }
}

fn main_header(inputfile: &mut File, header_version: u8) -> Result<HeaderType> {
    match header_version {
        1 => {
            eprintln!("{ERROR_UNSUPPORTED_HEADER_VERSION}");
            exit(EXIT_STATUS_ERROR);
        },
        2 => match MainHeader::decode_directly(inputfile) {
            Ok(main_header) => return Ok(HeaderType::MainHeader(main_header)),
            Err(err_msg) => {
                eprintln!("{ERROR_PARSE_MAIN_HEADER} {err_msg}");
                exit(EXIT_STATUS_ERROR);
            }
        },
        version @ _ => {
            eprintln!("{ERROR_UNSUPPORTED_HEADER_VERSION}; Version {version}");
            exit(EXIT_STATUS_ERROR);
        },
    }
}

fn segment_header(inputfile: &mut File, header_version: u8) -> Result<HeaderType> {
    match header_version {
        1 => {
                eprintln!("{ERROR_UNSUPPORTED_HEADER_VERSION}");
                exit(EXIT_STATUS_ERROR);
        },
        2 => match SegmentHeader::decode_directly(inputfile) {
            Ok(segment_header) => return Ok(HeaderType::SegmentHeader(segment_header)),
            Err(err_msg) => {
                eprintln!("{ERROR_PARSE_SEGMENT_HEADER}{err_msg}");
                exit(EXIT_STATUS_ERROR);
            }
        },
        version @ _ => {
            eprintln!("{ERROR_UNSUPPORTED_HEADER_VERSION}; Version {version}");
            exit(EXIT_STATUS_ERROR);
        }
    }
}