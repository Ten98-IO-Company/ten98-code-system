// Minimal declarations for the Node built-ins the architecture checker uses. @types/node is
// not an approved dependency of @ten98/runtime, so this stays limited to the calls made in check.mts.
declare module 'node:fs' {
  interface Dirent {
    name: string;
    isDirectory(): boolean;
    isFile(): boolean;
    isSymbolicLink(): boolean;
  }
  export function readFileSync(path: string | URL, encoding: 'utf8'): string;
  export function readFileSync(path: string | URL): Uint8Array;
  export function writeFileSync(path: string, data: string): void;
  export function realpathSync(path: string): string;
  export function existsSync(path: string): boolean;
  export function readdirSync(path: string, options: { withFileTypes: true }): Dirent[];
  export function lstatSync(path: string): { isSymbolicLink(): boolean };
}

declare module 'node:path' {
  export function resolve(...paths: string[]): string;
  export function relative(from: string, to: string): string;
  export function basename(path: string): string;
}

declare module 'node:crypto' {
  export function createHash(algorithm: string): { update(data: Uint8Array): { digest(encoding: 'hex'): string } };
}

declare module 'node:child_process' {
  export function spawnSync(command: string, args: string[], options: {
    cwd?: string;
    input?: string | Uint8Array;
    encoding: 'utf8';
    timeout?: number;
    maxBuffer?: number;
    windowsHide?: boolean;
  }): { error?: Error; status: number | null; stdout: string; stderr: string };
}

declare module 'node:module' {
  interface NodeRequire {
    (id: string): unknown;
    resolve(id: string): string;
  }
  export function createRequire(path: string): NodeRequire;
}

declare module 'node:url' {
  export function fileURLToPath(url: string | URL): string;
}

declare const process: {
  versions: { node: string };
  argv: string[];
  execPath: string;
  exitCode?: number;
};
