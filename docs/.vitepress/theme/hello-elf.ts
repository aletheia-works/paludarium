/**
 * Builds a minimal static x86-64 Linux ELF executable that writes `message`
 * to standard output with write(2) and ends with exit_group(2).
 *
 * The program is one PT_LOAD segment at 0x400000:
 *
 *   mov  eax, 1            ; write
 *   mov  edi, 1            ; stdout
 *   lea  rsi, [rip + msg]
 *   mov  edx, len
 *   syscall
 *   mov  eax, 231          ; exit_group
 *   xor  edi, edi          ; status 0
 *   syscall
 * msg:
 *   db   message
 */
const BASE = 0x400000n
const EHDR_SIZE = 64
const PHDR_SIZE = 56
const CODE_OFFSET = EHDR_SIZE + PHDR_SIZE
/** Longest message the demo accepts, in bytes. */
export const MAX_MESSAGE_BYTES = 4096

export function helloElf(message: string): Uint8Array {
  const text = new TextEncoder().encode(message)
  if (text.length > MAX_MESSAGE_BYTES) {
    throw new RangeError(`message is longer than ${MAX_MESSAGE_BYTES} bytes`)
  }
  const code = [
    0xb8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
    0xbf, 0x01, 0x00, 0x00, 0x00, // mov edi, 1
    0x48, 0x8d, 0x35, 0x10, 0x00, 0x00, 0x00, // lea rsi, [rip + 16]
    0xba, ...u32(text.length), // mov edx, len
    0x0f, 0x05, // syscall
    0xb8, 0xe7, 0x00, 0x00, 0x00, // mov eax, 231
    0x31, 0xff, // xor edi, edi
    0x0f, 0x05, // syscall
  ]
  const size = CODE_OFFSET + code.length + text.length
  const elf = new Uint8Array(size)
  const view = new DataView(elf.buffer)
  elf.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0], 0) // ELF64, little endian, SysV
  view.setUint16(16, 2, true) // ET_EXEC
  view.setUint16(18, 0x3e, true) // EM_X86_64
  view.setUint32(20, 1, true) // EV_CURRENT
  view.setBigUint64(24, BASE + BigInt(CODE_OFFSET), true) // e_entry
  view.setBigUint64(32, BigInt(EHDR_SIZE), true) // e_phoff
  view.setUint16(52, EHDR_SIZE, true) // e_ehsize
  view.setUint16(54, PHDR_SIZE, true) // e_phentsize
  view.setUint16(56, 1, true) // e_phnum
  const ph = EHDR_SIZE
  view.setUint32(ph, 1, true) // PT_LOAD
  view.setUint32(ph + 4, 5, true) // PF_R | PF_X
  view.setBigUint64(ph + 16, BASE, true) // p_vaddr
  view.setBigUint64(ph + 24, BASE, true) // p_paddr
  view.setBigUint64(ph + 32, BigInt(size), true) // p_filesz
  view.setBigUint64(ph + 40, BigInt(size), true) // p_memsz
  view.setBigUint64(ph + 48, 0x1000n, true) // p_align
  elf.set(code, CODE_OFFSET)
  elf.set(text, CODE_OFFSET + code.length)
  return elf
}

function u32(value: number): number[] {
  return [value & 0xff, (value >>> 8) & 0xff, (value >>> 16) & 0xff, (value >>> 24) & 0xff]
}
