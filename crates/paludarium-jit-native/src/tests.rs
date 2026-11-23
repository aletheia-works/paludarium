//! Compiled code does what the interpreter does: each form, and runs of
//! forms, from random states, compared with `paludarium_cpu::step`.
use paludarium_cpu::compile::{Compiler, Fast, Form, REP_CHUNK};
use paludarium_cpu::{CpuState, flag, reg, step};
use paludarium_decoder::decode;
use paludarium_mmu::{AddressSpace, MappingKind, Prot, Userfault};
use paludarium_types::{GuestAddr, PAGE_SIZE};

use crate::native::NativeCompiler;

const CODE: u64 = 0x40_0000;
const DATA: u64 = 0x60_0000;
const DATA_LEN: usize = 0x2000;
const STACK: u64 = 0x80_0000;
const STACK_LEN: usize = 0x2000;

/// Instructions that have a form, run with registers that point at data,
/// the stack, past the end of the data, unmapped memory or anywhere.
const FORMS: &[&[u8]] = &[
    &[0x90],
    &[0xf3, 0x0f, 0x1e, 0xfa],
    &[0x0f, 0x1f, 0x44, 0x00, 0x00],
    &[0x48, 0x89, 0xd8],
    &[0x89, 0xd8],
    &[0x88, 0xd8],
    &[0x40, 0x88, 0xe7],
    &[0x66, 0x89, 0xd8],
    &[0x45, 0x89, 0xc8],
    &[0x48, 0xc7, 0xc0, 0xf0, 0xff, 0xff, 0xff],
    &[0xb8, 0x78, 0x56, 0x34, 0x12],
    &[0x48, 0xb8, 1, 2, 3, 4, 5, 6, 7, 0x88],
    &[0xb0, 0x80],
    &[0x48, 0x8b, 0x03],
    &[0x8b, 0x43, 0x08],
    &[0x48, 0x8b, 0x04, 0xcb],
    &[0x8a, 0x03],
    &[0x66, 0x8b, 0x43, 0xff],
    &[0x64, 0x48, 0x8b, 0x03],
    &[0x67, 0x8b, 0x03],
    &[0x48, 0x8b, 0x05, 0x00, 0x00, 0x20, 0x00],
    &[0x48, 0x89, 0x03],
    &[0x89, 0x43, 0x04],
    &[0x88, 0x03],
    &[0x66, 0x89, 0x03],
    &[0x48, 0xc7, 0x03, 0x80, 0xff, 0xff, 0xff],
    &[0xc6, 0x03, 0x7f],
    &[0x48, 0x89, 0x44, 0xcb, 0xf9],
    &[0x0f, 0xb6, 0x03],
    &[0x48, 0x0f, 0xb7, 0x03],
    &[0x66, 0x0f, 0xb6, 0x03],
    &[0x48, 0x8d, 0x44, 0xcb, 0x10],
    &[0x67, 0x48, 0x8d, 0x03],
    &[0x48, 0x8d, 0x05, 0x10, 0x00, 0x00, 0x00],
    &[0x53],
    &[0x54],
    &[0x41, 0x50],
    &[0x5b],
    &[0x5c],
    &[0x41, 0x58],
    &[0x74, 0x05],
    &[0x75, 0xfb],
    &[0x0f, 0x8c, 0x00, 0x01, 0x00, 0x00],
    &[0x72, 0x05],
    &[0x73, 0x05],
    &[0x76, 0x05],
    &[0x77, 0x05],
    &[0x78, 0x05],
    &[0x79, 0x05],
    &[0x7a, 0x05],
    &[0x7b, 0x05],
    &[0x7c, 0x05],
    &[0x7d, 0x05],
    &[0x7e, 0x05],
    &[0x7f, 0x05],
    &[0x70, 0x05],
    &[0x71, 0x05],
    &[0xeb, 0x05],
    &[0xe9, 0x00, 0x10, 0x00, 0x00],
    &[0xe8, 0x00, 0x10, 0x00, 0x00],
    &[0xc3],
    // indirect jmp and call, through a register or 8 bytes of memory
    &[0xff, 0xe0],
    &[0x41, 0xff, 0xe3],
    &[0xff, 0x23],
    &[0xff, 0x25, 0x00, 0x00, 0x20, 0x00],
    &[0xff, 0xd0],
    &[0xff, 0xd4],
    &[0x41, 0xff, 0xd3],
    &[0xff, 0x13],
    &[0xff, 0x14, 0xcb],
    &[0xff, 0x14, 0x24],
    // push of 8 bytes of memory, also of rsp's own stack slots
    &[0xff, 0x33],
    &[0x41, 0xff, 0x30],
    &[0xff, 0x34, 0xcb],
    &[0xff, 0x34, 0x24],
    &[0xff, 0x74, 0x24, 0x08],
    &[0xff, 0x35, 0x00, 0x00, 0x20, 0x00],
    &[0x64, 0xff, 0x33],
    &[0x48, 0x01, 0xd8],
    &[0x48, 0x29, 0xd8],
    &[0x21, 0xd8],
    &[0x09, 0xd8],
    &[0x31, 0xc0],
    &[0x66, 0x31, 0xd8],
    &[0x00, 0xd8],
    &[0x28, 0xd8],
    &[0x66, 0x01, 0xd8],
    &[0x01, 0xd8],
    &[0x29, 0xd8],
    &[0x48, 0x39, 0xd8],
    &[0x39, 0xd8],
    &[0x38, 0xd8],
    &[0x48, 0x85, 0xc0],
    &[0x48, 0x83, 0xc0, 0xf0],
    &[0x83, 0xe0, 0x0f],
    &[0x48, 0x83, 0xf8, 0x7f],
    &[0xf6, 0xc3, 0x01],
    &[0x3c, 0x05],
    &[0x48, 0x3d, 0x00, 0x00, 0x00, 0x80],
    &[0x83, 0xe8, 0x01],
    &[0x48, 0x83, 0xec, 0x18],
    &[0x48, 0x81, 0xe4, 0xf0, 0xff, 0xff, 0xff],
    &[0x48, 0x39, 0x03],
    &[0x80, 0x3b, 0x2f],
    &[0x48, 0x83, 0x3b, 0x00],
    &[0xf6, 0x03, 0x01],
    &[0x48, 0x85, 0x03],
    &[0x66, 0x83, 0x7b, 0x02, 0xff],
    // movzx, movsx, movsxd, cbw, cwde, cdqe
    &[0x0f, 0xb6, 0xc3],
    &[0x48, 0x0f, 0xb6, 0xc3],
    &[0x0f, 0xb7, 0xc3],
    &[0x66, 0x0f, 0xb6, 0xc3],
    &[0x0f, 0xbe, 0xc3],
    &[0x48, 0x0f, 0xbf, 0xc3],
    &[0x66, 0x0f, 0xbe, 0xc3],
    &[0x48, 0x63, 0xc3],
    &[0x63, 0xc3],
    &[0x4c, 0x63, 0xc0],
    &[0x48, 0x98],
    &[0x98],
    &[0x66, 0x98],
    &[0x48, 0x63, 0x03],
    &[0x0f, 0xbe, 0x03],
    &[0x48, 0x0f, 0xbf, 0x43, 0x02],
    &[0x66, 0x0f, 0xbe, 0x03],
    // lea r32, lea r16
    &[0x8d, 0x03],
    &[0x8d, 0x44, 0xcb, 0x10],
    &[0x66, 0x8d, 0x03],
    &[0x44, 0x8d, 0x04, 0x0b],
    &[0x67, 0x8d, 0x03],
    // setcc, cmovcc
    &[0x0f, 0x94, 0xc0],
    &[0x0f, 0x92, 0xc3],
    &[0x41, 0x0f, 0x95, 0xc0],
    &[0x40, 0x0f, 0x9f, 0xc6],
    &[0x0f, 0x9a, 0xc1],
    &[0x0f, 0x9c, 0x03],
    &[0x0f, 0x93, 0x43, 0x01],
    &[0x48, 0x0f, 0x44, 0xc3],
    &[0x0f, 0x42, 0xc3],
    &[0x66, 0x0f, 0x4f, 0xc3],
    &[0x4c, 0x0f, 0x45, 0xc0],
    &[0x0f, 0x46, 0xc8],
    &[0x48, 0x0f, 0x43, 0x03],
    &[0x0f, 0x4c, 0x43, 0x04],
    // inc, dec, neg, not
    &[0x48, 0xff, 0xc0],
    &[0xff, 0xc8],
    &[0xfe, 0xc0],
    &[0x66, 0xff, 0xc0],
    &[0x49, 0xff, 0xc8],
    &[0x48, 0xf7, 0xd8],
    &[0xf7, 0xd8],
    &[0xf6, 0xd8],
    &[0x48, 0xf7, 0xd0],
    &[0xf7, 0xd0],
    &[0x66, 0xf7, 0xd0],
    &[0xf6, 0xd0],
    &[0x48, 0xff, 0x03],
    &[0xff, 0x4b, 0x04],
    &[0xfe, 0x03],
    &[0x48, 0xf7, 0x1b],
    &[0xf7, 0x13],
    &[0x66, 0xff, 0x0b],
    // op r, [m]
    &[0x48, 0x03, 0x03],
    &[0x2b, 0x43, 0x08],
    &[0x64, 0x48, 0x2b, 0x03],
    &[0x48, 0x3b, 0x03],
    &[0x23, 0x03],
    &[0x0a, 0x03],
    &[0x66, 0x33, 0x43, 0x01],
    &[0x48, 0x3b, 0x04, 0xcb],
    &[0x44, 0x2b, 0x03],
    // op [m], r/imm
    &[0x48, 0x01, 0x03],
    &[0x48, 0x83, 0x03, 0x01],
    &[0x81, 0x2b, 0x00, 0x01, 0x00, 0x00],
    &[0x09, 0x43, 0x04],
    &[0x80, 0x23, 0x0f],
    &[0x66, 0x31, 0x03],
    &[0x48, 0x83, 0x6c, 0x24, 0x08, 0x01],
    &[0x64, 0x48, 0x01, 0x03],
    &[0x30, 0x03],
    // shifts and rotates by an immediate
    &[0x48, 0xc1, 0xe8, 0x05],
    &[0xc1, 0xe8, 0x1f],
    &[0x48, 0xc1, 0xe0, 0x03],
    &[0xc1, 0xe0, 0x00],
    &[0x48, 0xd1, 0xf8],
    &[0xc1, 0xf8, 0x07],
    &[0x66, 0xc1, 0xe0, 0x11],
    &[0x66, 0xc1, 0xe8, 0x10],
    &[0xc0, 0xe8, 0x09],
    &[0xc0, 0xf8, 0x1f],
    &[0x48, 0xc1, 0xc0, 0x0d],
    &[0xd1, 0xc8],
    &[0x66, 0xc1, 0xc8, 0x10],
    &[0xc0, 0xc0, 0x01],
    &[0x49, 0xc1, 0xe8, 0x3f],
    &[0x48, 0xd1, 0xe0],
    &[0xc0, 0xc8, 0x23],
    &[0x48, 0xc1, 0xc0, 0x40],
    &[0x48, 0xc1, 0xc8, 0x3f],
    &[0x66, 0xd1, 0xc0],
    // high-byte registers
    &[0xb4, 0x12],
    &[0x88, 0xe0],
    &[0x88, 0xc4],
    &[0x88, 0xfd],
    &[0x8a, 0x23],
    &[0x88, 0x33],
    &[0xf6, 0xc4, 0x01],
    &[0x80, 0xcc, 0x08],
    &[0x80, 0xe4, 0x0f],
    &[0x30, 0xc4],
    &[0x38, 0xcf],
    &[0x84, 0xe4],
    &[0x02, 0x23],
    &[0x20, 0x33],
    &[0x0f, 0xb6, 0xc4],
    &[0x0f, 0xbe, 0xcf],
    &[0x66, 0x0f, 0xb6, 0xdc],
    &[0xfe, 0xc4],
    &[0xfe, 0xcf],
    &[0xf6, 0xdc],
    &[0xf6, 0xd7],
    &[0x0f, 0x94, 0xc4],
    &[0xd0, 0xe4],
    &[0xc0, 0xed, 0x03],
    &[0xc0, 0xc6, 0x05],
    &[0xd0, 0xfc],
    // shifts by cl, push imm
    &[0xd3, 0xe0],
    &[0x48, 0xd3, 0xe8],
    &[0x48, 0xd3, 0xfa],
    &[0xd2, 0xe0],
    &[0x66, 0xd3, 0xeb],
    &[0x41, 0xd3, 0xf9],
    &[0xd2, 0xe4],
    &[0x48, 0xd3, 0xe1],
    &[0xd2, 0xf8],
    &[0x66, 0xd3, 0xe0],
    &[0x6a, 0x01],
    &[0x6a, 0xff],
    &[0x68, 0x78, 0x56, 0x34, 0x12],
    &[0x68, 0x00, 0x00, 0x00, 0x80],
    // mul and imul
    &[0x48, 0xf7, 0xe3],
    &[0xf7, 0xe1],
    &[0x66, 0xf7, 0xe3],
    &[0xf6, 0xe3],
    &[0xf6, 0xe4],
    &[0x48, 0xf7, 0xe0],
    &[0x48, 0xf7, 0xe2],
    &[0x48, 0xf7, 0xe9],
    &[0xf7, 0xeb],
    &[0xf6, 0xe9],
    &[0x66, 0xf7, 0xee],
    &[0x48, 0x0f, 0xaf, 0xc3],
    &[0x0f, 0xaf, 0xc1],
    &[0x66, 0x0f, 0xaf, 0xd3],
    &[0x4d, 0x0f, 0xaf, 0xc1],
    &[0x48, 0x6b, 0xc3, 0x07],
    &[0x6b, 0xca, 0xfd],
    &[0x48, 0x69, 0xc3, 0x78, 0x56, 0x34, 0x12],
    &[0x66, 0x69, 0xd9, 0x34, 0x12],
    &[0x69, 0xc0, 0xff, 0xff, 0xff, 0x7f],
    // SSE moves and xor
    &[0x0f, 0x28, 0xc1],
    &[0x66, 0x0f, 0x6f, 0xca],
    &[0xf3, 0x0f, 0x6f, 0xd3],
    &[0x0f, 0x10, 0xc1],
    &[0x66, 0x0f, 0x28, 0xc1],
    &[0x66, 0x0f, 0x10, 0xc1],
    &[0x45, 0x0f, 0x28, 0xc1],
    &[0x0f, 0x10, 0x03],
    &[0x0f, 0x28, 0x03],
    &[0x66, 0x0f, 0x6f, 0x03],
    &[0xf3, 0x0f, 0x6f, 0x43, 0x10],
    &[0x66, 0x44, 0x0f, 0x6f, 0x04, 0xcb],
    &[0x0f, 0x11, 0x03],
    &[0x0f, 0x29, 0x03],
    &[0x66, 0x0f, 0x7f, 0x03],
    &[0xf3, 0x0f, 0x7f, 0x0b],
    &[0x66, 0x0f, 0x7f, 0x44, 0x24, 0xf0],
    &[0x66, 0x0f, 0xef, 0xc1],
    &[0x0f, 0x57, 0xc0],
    &[0x66, 0x45, 0x0f, 0xef, 0xc1],
    &[0x66, 0x0f, 0x6e, 0xc0],
    &[0x66, 0x48, 0x0f, 0x6e, 0xc0],
    &[0x66, 0x0f, 0x7e, 0xc0],
    &[0x66, 0x48, 0x0f, 0x7e, 0xc0],
    &[0xf3, 0x0f, 0x7e, 0xc1],
    &[0x66, 0x44, 0x0f, 0x6e, 0xc3],
    &[0x66, 0x49, 0x0f, 0x7e, 0xc1],
    // movd and movq between an xmm register and memory
    &[0x66, 0x0f, 0x6e, 0x03],
    &[0x66, 0x44, 0x0f, 0x6e, 0x0b],
    &[0x66, 0x0f, 0x7e, 0x03],
    &[0x66, 0x44, 0x0f, 0x7e, 0x4c, 0x24, 0xf0],
    &[0xf3, 0x0f, 0x7e, 0x03],
    &[0xf3, 0x44, 0x0f, 0x7e, 0x4c, 0xcb, 0x08],
    &[0x66, 0x48, 0x0f, 0x6e, 0x03],
    &[0x66, 0x0f, 0xd6, 0x03],
    &[0x66, 0x44, 0x0f, 0xd6, 0x4c, 0x24, 0xf0],
    &[0x66, 0x48, 0x0f, 0x7e, 0x03],
    &[0x64, 0xf3, 0x0f, 0x7e, 0x03],
    // movsd between an xmm register and memory
    &[0xf2, 0x0f, 0x10, 0x03],
    &[0xf2, 0x44, 0x0f, 0x10, 0x4c, 0xcb, 0x08],
    &[0xf2, 0x0f, 0x11, 0x03],
    &[0xf2, 0x44, 0x0f, 0x11, 0x4c, 0x24, 0xf0],
    &[0x64, 0xf2, 0x0f, 0x10, 0x03],
    // SSE shuffles, shifts, unpacks and pmovmskb
    &[0x66, 0x0f, 0x70, 0xc1, 0x1b],
    &[0x66, 0x0f, 0x70, 0xc0, 0x00],
    &[0x66, 0x45, 0x0f, 0x70, 0xc1, 0xe4],
    &[0xf2, 0x0f, 0x70, 0xc1, 0x1b],
    &[0xf2, 0x0f, 0x70, 0xc0, 0x00],
    &[0xf2, 0x45, 0x0f, 0x70, 0xc1, 0xe4],
    &[0xf3, 0x0f, 0x70, 0xc1, 0x1b],
    &[0xf3, 0x44, 0x0f, 0x70, 0xc9, 0x39],
    &[0x66, 0x0f, 0x72, 0xf0, 0x05],
    &[0x66, 0x0f, 0x72, 0xd1, 0x1f],
    &[0x66, 0x0f, 0x72, 0xf2, 0x20],
    &[0x66, 0x0f, 0x72, 0xd3, 0x00],
    &[0x66, 0x41, 0x0f, 0x72, 0xf0, 0x03],
    &[0x66, 0x0f, 0x62, 0xc1],
    &[0x66, 0x0f, 0x60, 0xc1],
    &[0x66, 0x0f, 0x6c, 0xc1],
    &[0x66, 0x0f, 0x60, 0xc0],
    &[0x66, 0x45, 0x0f, 0x62, 0xc1],
    &[0x66, 0x0f, 0xd7, 0xc1],
    &[0x66, 0x44, 0x0f, 0xd7, 0xc8],
    &[0x66, 0x48, 0x0f, 0xd7, 0xc1],
    // SSE lane operations
    &[0x66, 0x0f, 0xf4, 0xc1],
    &[0x66, 0x45, 0x0f, 0xf4, 0xc1],
    &[0x66, 0x0f, 0xf4, 0xc0],
    &[0x66, 0x0f, 0xfe, 0xc1],
    &[0x66, 0x0f, 0xfa, 0xc1],
    &[0x66, 0x0f, 0xfa, 0xc0],
    &[0x66, 0x0f, 0xd4, 0xc1],
    &[0x66, 0x0f, 0xfb, 0xc1],
    &[0x66, 0x0f, 0xdb, 0xc1],
    &[0x66, 0x0f, 0xeb, 0xc1],
    &[0x66, 0x0f, 0xdf, 0xc1],
    &[0x66, 0x44, 0x0f, 0xdf, 0xc8],
    &[0x66, 0x0f, 0x74, 0xc1],
    &[0x66, 0x0f, 0x74, 0xc0],
    &[0x66, 0x45, 0x0f, 0x74, 0xc1],
    &[0x66, 0x0f, 0x75, 0xc1],
    &[0x66, 0x0f, 0x76, 0xc1],
    &[0x66, 0x44, 0x0f, 0x76, 0xc8],
    // SSE packs and the other unpacks
    &[0x66, 0x0f, 0x67, 0xc1],
    &[0x66, 0x0f, 0x67, 0xc0],
    &[0x66, 0x0f, 0x63, 0xc1],
    &[0x66, 0x0f, 0x6b, 0xc1],
    &[0x66, 0x45, 0x0f, 0x6b, 0xc1],
    &[0x66, 0x0f, 0x61, 0xc1],
    &[0x66, 0x0f, 0x68, 0xc1],
    &[0x66, 0x0f, 0x69, 0xc1],
    &[0x66, 0x0f, 0x6a, 0xc1],
    &[0x66, 0x0f, 0x6d, 0xc1],
    &[0x66, 0x0f, 0x68, 0xc0],
    // cmpxchg and xchg with memory, with lock or without
    &[0xf0, 0x0f, 0xb1, 0x0b],
    &[0x48, 0x0f, 0xb1, 0x0b],
    &[0xf0, 0x48, 0x0f, 0xb1, 0x13],
    &[0xf0, 0x0f, 0xb0, 0x0b],
    &[0x66, 0xf0, 0x0f, 0xb1, 0x0b],
    &[0x87, 0x0b],
    &[0x48, 0x87, 0x03],
    &[0x86, 0x23],
    &[0xf0, 0x87, 0x0b],
    &[0x66, 0x87, 0x13],
    // adc and sbb of a register and a register or an immediate, which
    // take CF
    &[0x48, 0x11, 0xd8],
    &[0x19, 0xd8],
    &[0x66, 0x11, 0xd8],
    &[0x10, 0xe0],
    &[0x1c, 0x01],
    &[0x48, 0x83, 0xd0, 0x7f],
    &[0x48, 0x83, 0xd8, 0xff],
    &[0x48, 0x19, 0xc0],
    // tzcnt, lzcnt, popcnt, bsf and bsr of registers; rcx is small, so
    // that it is sometimes 0
    &[0xf3, 0x48, 0x0f, 0xbc, 0xc3],
    &[0xf3, 0x0f, 0xbc, 0xc1],
    &[0x66, 0xf3, 0x0f, 0xbc, 0xc1],
    &[0xf3, 0x48, 0x0f, 0xbd, 0xc1],
    &[0xf3, 0x0f, 0xbd, 0xc3],
    &[0xf3, 0x48, 0x0f, 0xb8, 0xc3],
    &[0xf3, 0x0f, 0xb8, 0xc1],
    &[0x48, 0x0f, 0xbc, 0xc1],
    &[0x0f, 0xbc, 0xc1],
    &[0x48, 0x0f, 0xbd, 0xc3],
    &[0x0f, 0xbd, 0xc1],
    &[0x66, 0x0f, 0xbd, 0xc1],
    // bt of a register by a register or an immediate
    &[0x48, 0x0f, 0xa3, 0xd8],
    &[0x0f, 0xa3, 0xc8],
    &[0x66, 0x0f, 0xa3, 0xc8],
    &[0x48, 0x0f, 0xba, 0xe0, 0x3f],
    &[0x0f, 0xba, 0xe0, 0x25],
    // bswap
    &[0x48, 0x0f, 0xc8],
    &[0x0f, 0xc8],
    &[0x49, 0x0f, 0xc9],
    &[0x41, 0x0f, 0xcb],
    // bsf, bsr, tzcnt and lzcnt of 0, after which bsf and bsr keep the
    // whole destination
    &[0x31, 0xdb, 0x0f, 0xbc, 0xc3],
    &[0x31, 0xdb, 0x66, 0x0f, 0xbd, 0xc3],
    &[0x31, 0xdb, 0xf3, 0x0f, 0xbc, 0xc3],
    &[0x31, 0xdb, 0xf3, 0x48, 0x0f, 0xbd, 0xc3],
    // string moves, once and repeated (repne repeats as rep), forward or,
    // with DF set, back; fs adds its base to rsi
    &[0xa4],
    &[0x66, 0xa5],
    &[0xa5],
    &[0x48, 0xa5],
    &[0x64, 0xa4],
    &[0xf3, 0xa4],
    &[0xf3, 0x66, 0xa5],
    &[0xf3, 0xa5],
    &[0xf3, 0x48, 0xa5],
    &[0xf2, 0xa4],
    &[0x64, 0xf3, 0x48, 0xa5],
    // div and idiv of a register
    &[0x48, 0xf7, 0xf3],
    &[0xf7, 0xf1],
    &[0x66, 0xf7, 0xf3],
    &[0xf6, 0xf3],
    &[0xf6, 0xf4],
    &[0x49, 0xf7, 0xf0],
    &[0x48, 0xf7, 0xfb],
    &[0xf7, 0xf9],
    &[0x66, 0xf7, 0xfb],
    &[0xf6, 0xfb],
    // Divisions of dividends that fit: rdx cleared, or set to the sign of
    // rax with mov and sar, as cqo and cdq (which have no form) would
    &[0x31, 0xd2, 0x48, 0xf7, 0xf3],
    &[0x48, 0x89, 0xc2, 0x48, 0xc1, 0xfa, 0x3f, 0x48, 0xf7, 0xfb],
    &[0x31, 0xd2, 0xf7, 0xf1],
    &[0x89, 0xc2, 0xc1, 0xfa, 0x1f, 0xf7, 0xf9],
    // A 128-bit dividend, which the helper divides: rdx 1 or -1
    &[0xba, 0x01, 0x00, 0x00, 0x00, 0x48, 0xf7, 0xf3],
    &[0x48, 0xc7, 0xc2, 0xff, 0xff, 0xff, 0xff, 0x48, 0xf7, 0xfb],
    // By -1, by 0, and quotients that do not fit: i64::MIN by -1 as a
    // 128-bit dividend and as a 64-bit one (edx:eax)
    &[
        0x48, 0xc7, 0xc3, 0xff, 0xff, 0xff, 0xff, 0x48, 0x89, 0xc2, 0x48, 0xc1, 0xfa, 0x3f, 0x48,
        0xf7, 0xfb,
    ],
    &[0x31, 0xdb, 0x48, 0xf7, 0xf3],
    &[0x31, 0xc9, 0xf7, 0xf9],
    &[
        0x48, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0x80, 0x48, 0xc7, 0xc2, 0xff, 0xff, 0xff, 0xff, 0x48,
        0xc7, 0xc3, 0xff, 0xff, 0xff, 0xff, 0x48, 0xf7, 0xfb,
    ],
    &[
        0xb8, 0, 0, 0, 0, 0xba, 0, 0, 0, 0x80, 0xb9, 0xff, 0xff, 0xff, 0xff, 0xf7, 0xf9,
    ],
];

struct Random(u64);

impl Random {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

fn space(code: &[u8], data: &[u8]) -> AddressSpace {
    let mut mem = AddressSpace::new();
    for (at, len, prot, kind) in [
        (CODE, 0x1000, Prot::READ_EXEC, MappingKind::ElfSegment),
        (
            DATA,
            DATA_LEN as u64,
            Prot::READ_WRITE,
            MappingKind::Anonymous,
        ),
        (
            STACK - STACK_LEN as u64,
            STACK_LEN as u64,
            Prot::READ_WRITE,
            MappingKind::Stack,
        ),
    ] {
        mem.map(Some(GuestAddr(at)), len, prot, kind).unwrap();
    }
    mem.write_initial(GuestAddr(CODE), code).unwrap();
    mem.write_initial(GuestAddr(DATA), data).unwrap();
    mem
}

fn contents(mem: &AddressSpace) -> (Vec<u8>, Vec<u8>) {
    let mut data = vec![0; DATA_LEN];
    let mut stack = vec![0; STACK_LEN];
    mem.read(GuestAddr(DATA), &mut data).unwrap();
    mem.read(GuestAddr(STACK - STACK_LEN as u64), &mut stack)
        .unwrap();
    (data, stack)
}

fn value(random: &mut Random) -> u64 {
    let r = random.next();
    match r % 7 {
        0 | 1 => DATA + (r >> 8) % DATA_LEN as u64,
        2 => STACK - (r >> 8) % 64,
        3 => DATA + DATA_LEN as u64 - (r >> 8) % 16,
        4 => 0x1000 + (r >> 8) % 0x1000,
        5 => (r >> 8) % 4,
        _ => random.next(),
    }
}

fn state(random: &mut Random) -> CpuState {
    let mut s = CpuState::new(GuestAddr(CODE), GuestAddr(STACK - 0x100));
    for gpr in &mut s.gpr {
        *gpr = value(random);
    }
    s.gpr[reg::RCX] = random.next() % 64;
    // DF too, so that string moves also step back.
    s.rflags = (random.next() & (flag::STATUS | flag::DF)) | flag::RESERVED1;
    s.fs_base = random.next() % 0x100;
    for x in &mut s.xmm {
        *x = u128::from(random.next()) | (u128::from(random.next()) << 64);
        // Half the registers get small or negative lanes, so that packs
        // also keep values rather than only saturate them.
        if random.next().is_multiple_of(2) {
            *x &= 0x81ff_81ff_81ff_81ff_81ff_81ff_81ff_81ff;
        }
    }
    s
}

/// The forms of `code`, instructions placed one after another at `CODE`.
fn forms(code: &[u8]) -> Vec<Form> {
    let mut forms = Vec::new();
    let mut offset = 0;
    while offset < code.len() {
        let i = decode(&code[offset..], GuestAddr(CODE + offset as u64)).unwrap();
        let fast = Fast::of(&i);
        assert_ne!(fast, Fast::None, "{:02x?} has no form", &code[offset..]);
        forms.push(Form {
            rip: i.rip.0,
            next: i.next_rip().0,
            fast,
        });
        offset += usize::from(i.len);
    }
    forms
}

/// Fills the thread's slots of the data and the stack pages, as accesses
/// of compiled code do, so that the next accesses go through them; the
/// bytes stay as they were.
fn warm(mem: &AddressSpace) {
    let pages = (DATA..DATA + DATA_LEN as u64).chain(STACK - STACK_LEN as u64..STACK);
    for page in pages.step_by(PAGE_SIZE as usize) {
        let value = mem.jit_read_value(GuestAddr(page), 8).unwrap();
        mem.jit_write_value(GuestAddr(page), 8, value).unwrap();
    }
}

/// Runs `code` compiled and in the interpreter from random states, every
/// other one with the slots of the pages filled ([`warm`]).
fn compare(compiler: &NativeCompiler, code: &[u8], random: &mut Random, rounds: usize) -> usize {
    let forms = forms(code);
    let compiled = compiler
        .compile(&forms)
        .unwrap_or_else(|| panic!("{code:02x?} did not compile"));
    let mut stopped = 0;
    for round in 0..rounds {
        let data: Vec<u8> = (0..DATA_LEN).map(|_| random.next() as u8).collect();
        let before = state(random);
        let (fast_memory, slow_memory) = (space(code, &data), space(code, &data));
        if round % 2 == 0 {
            warm(&fast_memory);
        }
        let generation = fast_memory.code_generation_cached();
        let mut fast = before.clone();
        let ran = compiled.run(&mut fast, &fast_memory, generation);
        assert!(ran <= forms.len());
        let mut slow = before.clone();
        for _ in 0..ran {
            step(&mut slow, &slow_memory).unwrap_or_else(|e| {
                panic!("{code:02x?} from {before:x?}: the interpreter stopped: {e:?}")
            });
        }
        assert_eq!(fast, slow, "{code:02x?} from {before:x?}, {ran} ran");
        assert_eq!(
            contents(&fast_memory),
            contents(&slow_memory),
            "{code:02x?} from {before:x?}"
        );
        // Stopping before an instruction of the block means it fails.
        if let Some(form) = forms.iter().find(|f| f.rip == fast.rip.0)
            && ran < forms.len()
            && forms[ran].rip == form.rip
        {
            stopped += 1;
            assert!(
                step(&mut slow.clone(), &slow_memory).is_err(),
                "{code:02x?} from {before:x?} stopped before {:#x}, which runs",
                form.rip
            );
        }
    }
    stopped
}

#[test]
fn every_form_does_what_the_interpreter_does() {
    let compiler = NativeCompiler::new(1, false).unwrap();
    let mut random = Random(0x9e37_79b9_7f4a_7c15);
    let mut stopped = 0;
    for code in FORMS {
        stopped += compare(&compiler, code, &mut random, 300);
    }
    assert!(stopped > 0, "no form failed");
}

#[test]
fn runs_of_forms_do_what_the_interpreter_does() {
    let compiler = NativeCompiler::new(1, false).unwrap();
    let mut random = Random(0x2545_f491_4f6c_dd1d);
    for _ in 0..400 {
        let len = 2 + random.next() % 10;
        let mut code = Vec::new();
        for _ in 0..len {
            let form = FORMS[(random.next() % FORMS.len() as u64) as usize];
            code.extend_from_slice(form);
        }
        compare(&compiler, &code, &mut random, 20);
    }
}

/// Runs `code`, one string move, compiled from `state` and steps the
/// interpreter once from the same state, and checks that both ran it once
/// to the same state and memory. Returns the state.
fn one_step_of(
    code: &[u8],
    state: &CpuState,
    fast: &AddressSpace,
    slow: &AddressSpace,
) -> CpuState {
    let compiler = NativeCompiler::new(1, false).unwrap();
    let compiled = compiler.compile(&forms(code)).unwrap();
    let mut compiled_state = state.clone();
    let ran = compiled.run(&mut compiled_state, fast, fast.code_generation_cached());
    let mut stepped = state.clone();
    step(&mut stepped, slow).unwrap();
    assert_eq!(ran, 1, "{code:02x?}");
    assert_eq!(compiled_state, stepped, "{code:02x?}");
    assert_eq!(contents(fast), contents(slow), "{code:02x?}");
    compiled_state
}

#[test]
fn a_repeated_move_runs_its_iterations_of_a_step_then_runs_again() {
    // rep movsb, from the data to the stack.
    let code = [0xf3, 0xa4];
    let data: Vec<u8> = (0..DATA_LEN).map(|n| n as u8).collect();
    let (fast, slow) = (space(&code, &data), space(&code, &data));
    let mut state = CpuState::new(GuestAddr(CODE), GuestAddr(STACK - 0x100));
    state.gpr[reg::RSI] = DATA;
    state.gpr[reg::RDI] = STACK - STACK_LEN as u64;
    state.gpr[reg::RCX] = REP_CHUNK + 100;
    let state = one_step_of(&code, &state, &fast, &slow);
    assert_eq!(state.rip, GuestAddr(CODE));
    assert_eq!(state.gpr[reg::RCX], 100);
    let state = one_step_of(&code, &state, &fast, &slow);
    assert_eq!(state.rip, GuestAddr(CODE + 2));
    assert_eq!(state.gpr[reg::RCX], 0);
}

#[test]
fn a_repeated_move_that_faults_after_an_iteration_ends_its_step_there() {
    // rep movsq to the last 16 bytes of the data and on.
    let code = [0xf3, 0x48, 0xa5];
    let (fast, slow) = (space(&code, &[7; DATA_LEN]), space(&code, &[7; DATA_LEN]));
    let mut state = CpuState::new(GuestAddr(CODE), GuestAddr(STACK - 0x100));
    state.gpr[reg::RSI] = STACK - STACK_LEN as u64;
    state.gpr[reg::RDI] = DATA + DATA_LEN as u64 - 16;
    state.gpr[reg::RCX] = 4;
    let state = one_step_of(&code, &state, &fast, &slow);
    assert_eq!(state.rip, GuestAddr(CODE));
    assert_eq!(state.gpr[reg::RCX], 2);
    assert_eq!(state.gpr[reg::RDI], DATA + DATA_LEN as u64);
    // The next iteration faults at once: the code runs nothing.
    let compiler = NativeCompiler::new(1, false).unwrap();
    let compiled = compiler.compile(&forms(&code)).unwrap();
    let mut again = state.clone();
    assert_eq!(
        compiled.run(&mut again, &fast, fast.code_generation_cached()),
        0
    );
    assert_eq!(again, state);
    assert!(step(&mut state.clone(), &slow).is_err());
}

#[test]
fn a_form_that_faults_runs_nothing() {
    let compiler = NativeCompiler::new(1, false).unwrap();
    // mov rax, [rbx] with rbx unmapped.
    let code = [0x48, 0x8b, 0x03];
    let compiled = compiler.compile(&forms(&code)).unwrap();
    let memory = space(&code, &[]);
    let mut state = CpuState::new(GuestAddr(CODE), GuestAddr(STACK - 0x100));
    state.gpr[reg::RBX] = 0x1000;
    let before = state.clone();
    assert_eq!(
        compiled.run(&mut state, &memory, memory.code_generation_cached()),
        0
    );
    assert_eq!(state, before);
}

#[test]
fn an_increment_of_memory_it_cannot_write_runs_nothing() {
    let compiler = NativeCompiler::new(1, false).unwrap();
    // inc dword [rbx] with rbx at the code, which reads but does not write.
    let code = [0xff, 0x03];
    let compiled = compiler.compile(&forms(&code)).unwrap();
    let memory = space(&code, &[]);
    let mut state = CpuState::new(GuestAddr(CODE), GuestAddr(STACK - 0x100));
    state.gpr[reg::RBX] = CODE;
    let before = state.clone();
    assert_eq!(
        compiled.run(&mut state, &memory, memory.code_generation_cached()),
        0
    );
    assert_eq!(state, before);
}

#[test]
fn an_operation_on_memory_it_cannot_write_runs_nothing() {
    let compiler = NativeCompiler::new(1, false).unwrap();
    // add [rbx], rax with rbx at the code, which reads but does not write.
    let code = [0x48, 0x01, 0x03];
    let compiled = compiler.compile(&forms(&code)).unwrap();
    let memory = space(&code, &[]);
    let mut state = CpuState::new(GuestAddr(CODE), GuestAddr(STACK - 0x100));
    state.gpr[reg::RBX] = CODE;
    state.gpr[reg::RAX] = 1;
    let before = state.clone();
    assert_eq!(
        compiled.run(&mut state, &memory, memory.code_generation_cached()),
        0
    );
    assert_eq!(state, before);
    let mut first = [0; 3];
    memory.read(GuestAddr(CODE), &mut first).unwrap();
    assert_eq!(first, code);
}

/// How long compiling takes, for measuring: `cargo test --release -p
/// paludarium-jit-native -- --ignored --nocapture compile_time`.
#[test]
#[ignore = "measures; prints only"]
fn compile_time() {
    let variants: [&[(&str, &str)]; 4] = [
        &[("opt_level", "none")],
        &[("opt_level", "speed")],
        &[("opt_level", "none"), ("regalloc_algorithm", "single_pass")],
        &[
            ("opt_level", "speed"),
            ("regalloc_algorithm", "single_pass"),
        ],
    ];
    for set in variants {
        let compiler = NativeCompiler::with_settings(1, false, set).unwrap();
        for len in [1, 7, 20] {
            let mut random = Random(0x1234_5678_9abc_def1);
            let blocks: Vec<Vec<Form>> = (0..300)
                .map(|_| {
                    let mut code = Vec::new();
                    for _ in 0..len {
                        let form = FORMS[(random.next() % FORMS.len() as u64) as usize];
                        code.extend_from_slice(form);
                    }
                    forms(&code)
                })
                .collect();
            let started = std::time::Instant::now();
            let mut bytes = 0;
            for forms in &blocks {
                bytes += compiler.machine_code(forms).unwrap().len();
            }
            let elapsed = started.elapsed();
            println!(
                "{set:?} len {len}: {:.1} us per block, {} bytes per block",
                elapsed.as_secs_f64() * 1e6 / blocks.len() as f64,
                bytes / blocks.len()
            );
        }
    }
}

#[test]
fn a_block_compiled_in_the_background_runs_once_it_is_ready() {
    let compiler = NativeCompiler::new(1, true).unwrap();
    // mov eax, 0x12345678; add rax, rbx
    let code = [0xb8, 0x78, 0x56, 0x34, 0x12, 0x48, 0x01, 0xd8];
    let compiled = compiler.compile(&forms(&code)).unwrap();
    let memory = space(&code, &[]);
    let generation = memory.code_generation_cached();
    let started = std::time::Instant::now();
    loop {
        let mut state = CpuState::new(GuestAddr(CODE), GuestAddr(STACK - 0x100));
        state.gpr[reg::RBX] = 1;
        let before = state.clone();
        match compiled.run(&mut state, &memory, generation) {
            0 => {
                assert_eq!(state, before, "a block not yet compiled changed the state");
                assert!(
                    started.elapsed() < std::time::Duration::from_secs(60),
                    "the block was never compiled"
                );
                std::thread::yield_now();
            }
            ran => {
                assert_eq!(ran, 2);
                assert_eq!(state.gpr[reg::RAX], 0x1234_5679);
                break;
            }
        }
    }
    // The same forms again reuse the code.
    let again = compiler.compile(&forms(&code)).unwrap();
    let mut state = CpuState::new(GuestAddr(CODE), GuestAddr(STACK - 0x100));
    assert_eq!(again.run(&mut state, &memory, generation), 2);
}

#[test]
fn an_sse_move_that_fails_runs_nothing() {
    let compiler = NativeCompiler::new(1, false).unwrap();
    // movaps [rbx], xmm0 at the code, then misaligned; movaps xmm0, [rbx]
    // unmapped.
    for (code, rbx) in [
        (&[0x0f, 0x29, 0x03][..], CODE),
        (&[0x0f, 0x29, 0x03][..], DATA + 8),
        (&[0x0f, 0x28, 0x03][..], DATA + 8),
        (&[0x0f, 0x10, 0x03][..], 0x1000),
    ] {
        let compiled = compiler.compile(&forms(code)).unwrap();
        let memory = space(code, &[]);
        let mut state = CpuState::new(GuestAddr(CODE), GuestAddr(STACK - 0x100));
        state.gpr[reg::RBX] = rbx;
        state.xmm[0] = u128::MAX;
        let before = state.clone();
        assert_eq!(
            compiled.run(&mut state, &memory, memory.code_generation_cached()),
            0,
            "{code:02x?}"
        );
        assert_eq!(state, before);
        let (_, data) = contents(&memory);
        assert!(data.iter().all(|&b| b == 0));
    }
}

/// A compare and exchange whose compare matches writes memory, as the
/// interpreter's does: rax is set to the bytes at the address first.
#[test]
fn a_compare_exchange_that_matches_does_what_the_interpreter_does() {
    let compiler = NativeCompiler::new(1, false).unwrap();
    let mut random = Random(0x2545_f491_4f6c_dd1d);
    for code in [
        &[0xf0, 0x0f, 0xb1, 0x0b][..],
        &[0x48, 0x0f, 0xb1, 0x0b][..],
        &[0xf0, 0x0f, 0xb0, 0x0b][..],
        &[0x66, 0xf0, 0x0f, 0xb1, 0x0b][..],
    ] {
        let compiled = compiler.compile(&forms(code)).unwrap();
        for _ in 0..50 {
            let data: Vec<u8> = (0..DATA_LEN).map(|_| random.next() as u8).collect();
            let mut before = state(&mut random);
            let offset = (random.next() % (DATA_LEN as u64 - 8)) as usize;
            before.gpr[reg::RBX] = DATA + offset as u64;
            before.gpr[reg::RAX] = u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap());
            let (fast_memory, slow_memory) = (space(code, &data), space(code, &data));
            let mut fast = before.clone();
            assert_eq!(
                compiled.run(
                    &mut fast,
                    &fast_memory,
                    fast_memory.code_generation_cached()
                ),
                1,
                "{code:02x?}"
            );
            let mut slow = before.clone();
            step(&mut slow, &slow_memory).unwrap();
            assert_eq!(fast, slow, "{code:02x?} from {before:x?}");
            assert_eq!(
                contents(&fast_memory),
                contents(&slow_memory),
                "{code:02x?}"
            );
            assert_ne!(contents(&fast_memory).0, data, "{code:02x?} wrote nothing");
        }
    }
}

/// `mov rcx, [rbx]; mov [rbx], rax` run with the slot of the data page
/// filled, after `protect` changed what the page allows: what ran, the
/// word there, and the memory. The load fills the slot again, at the new
/// epoch, so the store finds it holding the page for reads.
fn store_after(protect: impl FnOnce(&mut AddressSpace)) -> (usize, u64, AddressSpace) {
    let compiler = NativeCompiler::new(1, false).unwrap();
    let code = [0x48, 0x8b, 0x0b, 0x48, 0x89, 0x03];
    let compiled = compiler.compile(&forms(&code)).unwrap();
    let mut memory = space(&code, &[1; 8]);
    warm(&memory);
    protect(&mut memory);
    let mut state = CpuState::new(GuestAddr(CODE), GuestAddr(STACK - 0x100));
    state.gpr[reg::RBX] = DATA;
    state.gpr[reg::RAX] = 0x5555;
    let ran = compiled.run(&mut state, &memory, memory.code_generation_cached());
    let word = memory.read_u64(GuestAddr(DATA)).unwrap();
    (ran, word, memory)
}

#[test]
fn a_store_through_a_filled_slot_writes() {
    let (ran, word, _) = store_after(|_| {});
    assert_eq!((ran, word), (2, 0x5555));
}

#[test]
fn a_store_to_a_page_made_read_only_after_its_slot_was_filled_faults() {
    let (ran, word, _) = store_after(|m| {
        m.protect(GuestAddr(DATA), PAGE_SIZE, Prot::READ).unwrap();
    });
    assert_eq!((ran, word), (1, 0x0101_0101_0101_0101));
}

#[test]
fn a_store_to_a_page_userfaultfd_write_protects_faults() {
    let (ran, word, _) = store_after(|m| {
        let view = m.view();
        view.userfault_register(DATA, DATA + PAGE_SIZE, 7, Userfault::WP)
            .unwrap();
        view.userfault_write_protect(DATA, DATA + PAGE_SIZE, true)
            .unwrap();
    });
    assert_eq!((ran, word), (1, 0x0101_0101_0101_0101));
}

#[test]
fn a_store_after_clear_refs_makes_the_page_soft_dirty_again() {
    let soft_dirty = |m: &AddressSpace| m.view().pagemap(DATA, 1).unwrap()[0] >> 55 & 1;
    let mut cleared = None;
    let (ran, word, memory) = store_after(|m| {
        assert!(m.view().clear_soft_dirty());
        cleared = Some(soft_dirty(m));
    });
    assert_eq!((ran, word, cleared), (2, 0x5555, Some(0)));
    assert_eq!(soft_dirty(&memory), 1);
}

#[test]
fn a_store_to_an_executable_page_nothing_was_fetched_from_keeps_the_code() {
    let mut generation = 0;
    let (ran, word, memory) = store_after(|m| {
        m.protect(GuestAddr(DATA), PAGE_SIZE, Prot::from_bits(7).unwrap())
            .unwrap();
        generation = m.code_generation();
    });
    assert_eq!((ran, word), (2, 0x5555));
    assert_eq!(memory.code_generation(), generation);
}

#[test]
fn a_store_to_an_executable_page_an_instruction_was_fetched_from_moves_the_code() {
    let mut generation = 0;
    let (ran, word, memory) = store_after(|m| {
        m.protect(GuestAddr(DATA), PAGE_SIZE, Prot::from_bits(7).unwrap())
            .unwrap();
        m.fetch(GuestAddr(DATA), &mut [0]).unwrap();
        generation = m.code_generation();
    });
    assert_eq!((ran, word), (2, 0x5555));
    assert_ne!(memory.code_generation(), generation);
}
