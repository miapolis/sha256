// Copyright (c) 2022 Ethan Lerner
//
// This software is released under the MIT License.
// https://opensource.org/licenses/MIT

use std::fmt::Write;
use std::io::Read;
use std::mem::transmute;

const SQRT_CONST: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const CBRT_CONST: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

pub fn sha256(input: &str) -> String {
    let input_bytes = input.as_bytes();
    let padded = apply_padding(input_bytes);
    let blocks = create_blocks(padded);

    let mut hash = SQRT_CONST;
    for block in blocks {
        let schedule = create_message_schedule(&block);
        hash = do_compression(hash, &schedule);
    }

    get_digest(&hash)
}

fn apply_padding(bytes: &[u8]) -> Vec<u8> {
    let byte_length = bytes.len();
    let bit_length = byte_length * 8;

    let mut chunk_buffer = Vec::new();
    chunk_buffer.extend_from_slice(bytes);
    chunk_buffer.push(0x80);

    let padding_length = (55 - byte_length as isize).rem_euclid(64).abs() as usize;
    chunk_buffer.append(&mut vec![0x00; padding_length]);

    for i in (0..8).rev() {
        chunk_buffer.push((bit_length >> i * 8) as u8);
    }

    chunk_buffer
}

fn create_blocks(padded: Vec<u8>) -> Vec<[u8; 64]> {
    let mut blocks = Vec::new();
    for mut chunk in padded.chunks(64) {
        let mut block = [0u8; 64];
        chunk.read(&mut block).unwrap();
        blocks.push(block);
    }

    blocks
}

fn create_message_schedule(block: &[u8; 64]) -> [u32; 64] {
    let mut schedule: [u32; 64] = [0; 64];

    for i in 0..16 {
        schedule[i] = u32::from_be_bytes(block[i * 4..(i + 1) * 4].try_into().unwrap());
    }

    for i in 16..64 {
        let calculated: u32 = sig1(schedule[i - 2])
            .wrapping_add(schedule[i - 7])
            .wrapping_add(sig0(schedule[i - 15]))
            .wrapping_add(schedule[i - 16]);
        schedule[i] = calculated;
    }

    schedule
}

fn do_compression(initial: [u32; 8], schedule: &[u32; 64]) -> [u32; 8] {
    let mut registers: [u32; 8] = initial;

    for i in 0..64 {
        let word = schedule[i];
        let constant = CBRT_CONST[i];

        let temp1 = usig1(registers[4])
            .wrapping_add(ch(registers[4], registers[5], registers[6]))
            .wrapping_add(registers[7])
            .wrapping_add(constant)
            .wrapping_add(word);
        let temp2 = usig0(registers[0]).wrapping_add(maj(registers[0], registers[1], registers[2]));

        registers.rotate_right(1);
        registers[0] = temp1.wrapping_add(temp2);
        registers[4] = registers[4].wrapping_add(temp1);
    }

    for i in 0..8 {
        registers[i] = initial[i].wrapping_add(registers[i]);
    }

    registers
}

fn get_digest(compressed: &[u32; 8]) -> String {
    let mut bytes: [u8; 32] = [0; 32];
    for i in 0..8 {
        let transmuted: [u8; 4] = unsafe { transmute(compressed[i].to_be()) };
        bytes[i * 4..(i + 1) * 4].copy_from_slice(&transmuted);
    }

    let mut digest = String::with_capacity(64);
    for byte in bytes {
        write!(digest, "{:02x}", byte).unwrap();
    }
    digest
}

#[inline]
fn sig0(x: u32) -> u32 {
    x.rotate_right(7) ^ x.rotate_right(18) ^ x >> 3
}

#[inline]
fn sig1(x: u32) -> u32 {
    x.rotate_right(17) ^ x.rotate_right(19) ^ x >> 10
}

#[inline]
fn usig0(x: u32) -> u32 {
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
}

#[inline]
fn usig1(x: u32) -> u32 {
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
}

#[inline]
fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

#[inline]
fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256() {
        assert_eq!(
            sha256("The quick brown fox jumps over the lazy dog"),
            "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"
        );
        assert_eq!(
            sha256(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256("https://lerners.io"),
            "b9424adf20d7c73d4a104a5b8ad20c58499955ec63e9a9b9325ca880ff4276ec"
        );
        assert_eq!(
            sha256("t̵͖͋̽̀h̸̨̡͖́͘í̶̩́s̶̹̘̹̚͠ ̷̹͖͒͑t̸̫̻̻̆̒e̶͉̦̅x̷͓͚̄̚t̵̲̦͌ ̴̨̓́i̵͉͔͐̂s̵̢̗͑̽͠ ̵̨̪̉a̵̯̍̇ñ̶̘͋̈́n̷̹̟̦̄͝o̷̰̰͖̕y̵̢̟͎͑̅i̵̫͇͝n̸̤̱̐͑͐g̵͔̮͊̚"),
            "db5319868fb1edce187942f7efaa000b3b70c4b70d0d100ffc277f0705c434f9"
        );
        assert_eq!(
            sha256("😀 😃 😄 😁 😆 😅 😂"),
            "efbac19e898b65f12f8f394027453b39cd0a2cdb4c863d25bd76768e7e03ffee"
        );
        assert_eq!(
            sha256("☝💙  Ŵ𝕠𝕨  👍ൠ"),
            "5577d96bb5bbebcdddefda87ecc5a34410f20306ed55a51c28cd0633236f6352"
        );
        assert_eq!(
            sha256("ᴵ ᵃᵐ ʰᵃᵛⁱⁿᵍ ᵗᵒᵒ ᵐᵘᶜʰ ᶠᵘⁿ ʷⁱᵗʰ ᵗʰⁱˢ"),
            "f31df27bb16a5e5ea676a6dc874a6539e53535bfeaccaa845b78df3d7847ef91"
        );
        assert_eq!(
            sha256("🐚♜  ⓣⓗᎥˢ 𝐢𝓢 𝓹я𝐨𝔹ａ𝐁𝕃Ｙ ᵍόσᗪ 𝕖ⓝ𝐎ｕᎶн ค𝓵ʳε𝔸đ𝕪  🎈☺"),
            "bdbb529d28016a81b32bfc5a0d58bb9787abdb229c2bb18f0d3aa8c635c69e0f"
        );
    }
}
