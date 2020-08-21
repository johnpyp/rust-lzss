use itertools;
use std::env;
use std::fs::File;
use std::io::prelude::*;
use std::io::{BufReader, BufWriter};
use std::io::{Error, ErrorKind};

const MAX_REF_BITS: u32 = 12;
const MAX_LEN_BITS: u32 = 4;
const MIN_MATCH_BYTES: u32 = 2;

struct BitWriter<'a, T: Write> {
    bit_count: u8,
    buffer: u8,
    output: &'a mut T,
}

impl<'a, T: Write> BitWriter<'a, T> {
    pub fn new(output: &'a mut T) -> Self {
        BitWriter {
            bit_count: 0,
            buffer: 0,
            output,
        }
    }

    pub fn write_bits(&mut self, bits: u16, bit_count: u8) -> Result<(), Error> {
        for i in 0..bit_count {
            if self.bit_count == 8 {
                self.flush_to_output()?;
            }
            let offset = bit_count - 1 - i;
            let bit = (bits & (1 << offset)) >> offset;
            self.buffer <<= 1;
            self.buffer |= bit as u8;
            self.bit_count += 1;
        }
        Ok(())
    }

    pub fn flush(&mut self) -> Result<(), Error> {
        if self.bit_count > 0 {
            self.buffer <<= 8 - self.bit_count;
            self.output.write_all(&[self.buffer])?;
            self.output.flush()?;
        }
        Ok(())
    }

    fn flush_to_output(&mut self) -> Result<(), Error> {
        self.output.write_all(&[self.buffer])?;
        self.buffer = 0;
        self.bit_count = 0;
        Ok(())
    }
}

struct BitReader<'a, T: Read> {
    bit_count: u8,
    buffer: u8,
    iter: std::io::Bytes<&'a mut T>,
}

impl<'a, T: Read> BitReader<'a, T> {
    pub fn new(input: &'a mut T) -> Self {
        BitReader {
            bit_count: 0,
            buffer: 0,
            iter: input.bytes(),
        }
    }

    fn load_next_byte(&mut self) -> bool {
        match self.iter.next() {
            Some(Ok(v)) => {
                self.buffer = v;
                self.bit_count = 8;
                true
            }
            Some(Err(_)) | None => false,
        }
    }

    pub fn take_bits(&mut self, count: u8) -> (u16, u8) {
        let mut res: u16 = 0;
        let mut bits_taken: u8 = 0;
        for i in 0..count {
            if self.bit_count == 0 {
                if !self.load_next_byte() {
                    return (res, i);
                }
            }
            bits_taken += 1;

            let offset = self.bit_count - 1;
            let bit = (self.buffer & (1 << offset)) >> offset;
            self.bit_count -= 1;

            res <<= 1;
            res |= bit as u16;
        }
        (res, bits_taken)
    }
}

fn sub_list_idx<T: Eq>(haystack: &[T], needle: &[T]) -> isize {
    if needle.len() > haystack.len() {
        return -1;
    }
    'outer: for i in 0..(haystack.len() - needle.len() + 1) {
        for (j, x) in needle.iter().enumerate() {
            if haystack[i + j] != *x {
                continue 'outer;
            }
        }
        return i as isize;
    }
    -1
}

fn encode(input: &mut impl Read, output: &mut impl Write) -> Result<(), std::io::Error> {
    let max_match_len = 2usize.pow(MAX_LEN_BITS);
    let window_size = 2usize.pow(MAX_REF_BITS);
    let mut dict: Vec<u8> = Vec::new();

    let mut output_writer = BitWriter::new(output);
    let mut bytes = itertools::multipeek(input.bytes());

    while let Some(byte) = bytes.next() {
        let byte = byte?;
        let mut res = vec![byte.clone()];

        let mut offset: isize = -1;

        dict.push(res[0]);
        while res.len() < max_match_len - 1 {
            let v = match bytes.peek() {
                Some(Ok(v)) => v.clone(),
                Some(Err(_)) => return Err(Error::new(ErrorKind::Other, "Bytes peek failed!")),
                None => break,
            };
            res.push(v);
            let new_offset = sub_list_idx(&dict, &res);
            dict.push(v);
            if new_offset == -1 {
                res.pop();
                dict.pop();
                break;
            }
            offset = new_offset;
        }

        if res.len() <= MIN_MATCH_BYTES as usize {
            for byte in &res {
                output_writer.write_bits(0b1, 1)?;
                output_writer.write_bits(byte.clone() as u16, 8)?;
            }
        } else {
            output_writer.write_bits(0b0, 1)?;
            output_writer.write_bits(offset as u16, MAX_REF_BITS as u8)?;
            output_writer.write_bits(res.len() as u16, MAX_LEN_BITS as u8)?;
        }
        bytes.reset_peek();
        if res.len() > 1 {
            bytes.nth(res.len() - 2);
        }
        if dict.len() > window_size {
            dict.drain(0..(dict.len() - window_size));
        }
    }
    output_writer.flush()?;
    Ok(())
}

fn decode(input: &mut impl Read, output: &mut impl Write) -> Result<(), std::io::Error> {
    let window_size = 2usize.pow(MAX_REF_BITS);
    let mut dict: Vec<u8> = Vec::new();
    let mut input_reader = BitReader::new(input);

    while let (flag, 1) = input_reader.take_bits(1) {
        match flag {
            1 => {
                let (next_byte, count) = input_reader.take_bits(8);
                if count < 8 {
                    break;
                }
                output.write_all(&[next_byte as u8])?;
                dict.push(next_byte as u8);
            }
            0 => {
                let (offset, count) = input_reader.take_bits(MAX_REF_BITS as u8);
                if count < MAX_REF_BITS as u8 {
                    break;
                }
                let (length, count) = input_reader.take_bits(MAX_LEN_BITS as u8);
                if count < MAX_LEN_BITS as u8 {
                    break;
                }

                for i in 0..length {
                    let idx = offset + i;
                    let el = dict[idx as usize] as u8;
                    output.write_all(&[el])?;
                    dict.push(el);
                }
            }
            _ => panic!("Only 1s and 0s please!"),
        }
        if dict.len() > window_size {
            dict.drain(0..(dict.len() - window_size));
        }
    }
    Ok(())
}

fn main() -> Result<(), std::io::Error> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 4 {
        let usage = r#"
    Usage: cargo run <mode> <input file> <output file>

    modes:
        encode - compress input -> output
        decode - decompress input -> output
    "#;

        println!("{}", usage);
        return Ok(());
    }

    let mode = &args[1];

    let mut input_file = env::current_dir()?;
    input_file.push(&args[2]);
    let mut output_file = env::current_dir()?;
    output_file.push(&args[3]);

    println!("Mode: {}", mode);
    println!("Input file: {:?}", input_file);
    println!("Output file: {:?}", output_file);

    let mut input = BufReader::new(File::open(input_file)?);
    let mut output = BufWriter::new(File::create(output_file)?);
    match mode.as_str() {
        "decode" => {
            decode(&mut input, &mut output)?;
        }
        "encode" => {
            encode(&mut input, &mut output)?;
        }
        _ => println!("Mode '{}' does not exist!", mode),
    }

    println!("Done!");

    Ok(())
}

#[cfg(test)]
mod tests {

    use std::io::Cursor;

    use super::{decode, encode, BitReader, BitWriter};

    #[test]
    fn bit_writer_writes_correct_bits() {
        let mut mock = Cursor::new(Vec::new());

        {
            let mut bit_writer = BitWriter::new(&mut mock);

            bit_writer.write_bits(0b11, 2).unwrap();
            bit_writer.write_bits(0b00000000, 8).unwrap();
            bit_writer.write_bits(0b101010, 6).unwrap();
            bit_writer.flush().unwrap();
        }

        assert_eq!(mock.get_ref(), &vec![0b11000000 as u8, 0b00101010 as u8])
    }
    #[test]
    fn bit_writer_writes_correct_bits_2() {
        let mut mock = Cursor::new(Vec::new());

        {
            let mut bit_writer = BitWriter::new(&mut mock);

            bit_writer.write_bits(0b11, 2).unwrap();
            bit_writer.write_bits(0b00, 2).unwrap();
            bit_writer.write_bits(0b10, 2).unwrap();
            bit_writer.flush().unwrap();
        }

        assert_eq!(mock.get_ref(), &vec![0b11001000 as u8])
    }
    #[test]
    fn bit_reader_reads_correct_bits() {
        let base: [u8; 2] = [0b00001101, 0b11101011];
        let mut mock = Cursor::new(base);

        let mut bit_reader = BitReader::new(&mut mock);

        let (bin, bits_taken) = bit_reader.take_bits(2);
        assert!(bits_taken == 2);
        assert_eq!(bin, 0);

        let (bin, bits_taken) = bit_reader.take_bits(8);
        assert!(bits_taken == 8);
        assert_eq!(bin, 0b00110111);

        let (bin, bits_taken) = bit_reader.take_bits(2);
        assert!(bits_taken == 2);
        assert_eq!(bin, 0b10);

        let (bin, bits_taken) = bit_reader.take_bits(5);
        assert!(bits_taken == 4);
        assert_eq!(bin, 0b1011);
    }

    #[test]
    fn encode_is_correct() {
        let base = b"abcabcabc222222222222222";
        let mut mock_read = Cursor::new(base);
        let mut mock_write = Cursor::new(Vec::new());
        {
            encode(&mut mock_read, &mut mock_write).unwrap();
        }

        assert!(mock_write.get_ref().len() < base.len());
    }

    fn test_encode_decode(inp: &[u8]) {
        let mut base = inp;
        let mut orig_output = Vec::new();
        let mut final_output = Vec::new();
        {
            let mut mock_read = Cursor::new(&mut base);
            let mut mock_write = Cursor::new(&mut orig_output);
            encode(&mut mock_read, &mut mock_write).unwrap();
        }
        {
            let mut mock_read = Cursor::new(&mut orig_output);
            let mut mock_write = Cursor::new(&mut final_output);
            decode(&mut mock_read, &mut mock_write).unwrap();
        }

        assert_eq!(base.to_vec(), final_output);
    }

    #[test]
    fn encode_to_decode_works_1() {
        test_encode_decode(b"222222");
    }

    #[test]
    fn encode_to_decode_works_2() {
        test_encode_decode(b"abcabcabc222222222222222");
    }

    #[test]
    fn encode_to_decode_works_3() {
        test_encode_decode(b"abcabcabcabc");
    }

    #[test]
    fn encode_to_decode_works_4() {
        test_encode_decode(b"abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz");
    }

    #[test]
    fn encode_to_decode_works_5() {
        test_encode_decode(b"abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz");
    }
    #[test]
    fn encode_to_decode_works_6() {
        test_encode_decode(b"11111111111111111111111111111111111111112222222222222222222222222222222222222222222222222222222222222222222333333333333333333333333333333333333333333334455555555555555555554444444444444444444444444444");
    }
}
