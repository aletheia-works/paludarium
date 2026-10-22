export type ExitStatus = { kind: "exited"; code: number } | { kind: "signaled"; signal: number };
export class PaludariumError extends Error {
  kind: "unimplemented" | "internal" | "invalid-program" | "host";
  rip?: bigint;
  bytes?: Uint8Array;
  syscall?: number;
}
/**
 * One path of a tree to place, in the shape `snapshot()` returns, so a
 * snapshot can be passed back as it is. The kind comes from the type bits of
 * `mode`: a regular file, a directory or a symlink (whose permissions are
 * always 0o777). Paths that share an `inode` value become hard links to one
 * file or symlink; the value itself is not kept. `links` is recalculated.
 */
export interface FileSystemEntryInput {
  path: string;
  mode: number;
  /** Regular file bytes or symlink target bytes; empty or left out for directories. */
  content?: Uint8Array;
  inode?: bigint | number;
  links?: bigint | number;
  /** Modification time; 0 when left out. */
  mtimeNs?: bigint | number;
}
export interface FileSystemOptions {
  files?: Record<string, Uint8Array>;
  fileModes?: Record<string, number>;
  /** Placed after `files`. Not accepted by `run()` together with `filesystem`. */
  entries?: readonly FileSystemEntryInput[];
}
export interface FileSystemEntry {
  path: string;
  mode: number;
  inode: bigint;
  links: bigint;
  mtimeNs: bigint;
  /** Regular file bytes or symlink target bytes; empty for directories. */
  content: Uint8Array;
}
export interface PrivateFileSystem {
  dispose(): Promise<void>;
  snapshot(): Promise<FileSystemEntry[]>;
  remove(path: string, options?: { recursive?: boolean }): Promise<void>;
}
export interface RunOptions extends FileSystemOptions {
  program: string;
  cwd?: string;
  args?: string[];
  env?: Record<string, string>;
  tty?: { columns: number; rows: number } | null;
  jit?: boolean;
  filesystem?: PrivateFileSystem;
}
export interface Guest {
  stdin: WritableStream<Uint8Array>;
  stdout: ReadableStream<Uint8Array>;
  stderr: ReadableStream<Uint8Array>;
  exited: Promise<ExitStatus>;
  kill(): void;
}
export interface Launcher {
  createFileSystem(options?: FileSystemOptions): Promise<PrivateFileSystem>;
  run(options: RunOptions): Guest;
  diagnostics(): Promise<unknown>;
  dispose(): Promise<void>;
}
export interface PaludariumOptions { wasmUrl: string | URL; }
export type RunningGuest = Guest;
export type Paludarium = Launcher;
export function createPaludarium(options: PaludariumOptions): Promise<Paludarium>;
