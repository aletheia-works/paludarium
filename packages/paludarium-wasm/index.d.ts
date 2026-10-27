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
/** Limits on what a guest may take from the host; a limit left out is unlimited. */
export interface Limits {
  /**
   * The most tasks at once (1 to 4294967295): threads, and processes until
   * they are reaped, as a cgroup's `pids.max`. `clone` and `fork` beyond it
   * fail with `EAGAIN`.
   */
  tasks?: number;
  /**
   * The ceiling of `RLIMIT_NOFILE` (0 to 1048576), as Linux's `fs.nr_open`:
   * opening more files fails with `EMFILE`, and raising the hard limit above
   * it with `EPERM`.
   */
  openFiles?: number;
  /**
   * The most bytes of guest memory at once (0 to 4294967295), as a cgroup's
   * `memory.max`: a page counts from its first write until every process
   * that has it unmaps it or ends, and shared memory counts once, as does a
   * page that `fork` shares until a write copies it. A write beyond it ends
   * the process with `SIGKILL`, as the OOM killer does, and an `execve` that
   * does not fit fails with `ENOMEM`. File contents
   * and pipe and socket buffers are not counted.
   */
  memory?: number;
}
export interface RunOptions extends FileSystemOptions {
  program: string;
  cwd?: string;
  args?: string[];
  env?: Record<string, string>;
  tty?: { columns: number; rows: number } | null;
  jit?: boolean;
  limits?: Limits;
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
