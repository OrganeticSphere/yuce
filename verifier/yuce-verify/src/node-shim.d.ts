// The few Node.js APIs the CLI entry uses, declared here so that the build
// needs no @types package. They are loaded with dynamic import() only when
// running under Node.js, so the same bundle also loads in a browser.

declare module "node:crypto" {
  export function createHash(algorithm: string): {
    update(data: Uint8Array): unknown;
    digest(): Uint8Array;
  };
}

declare module "node:fs" {
  export const promises: {
    readFile(path: string): Promise<Uint8Array>;
    stat(path: string): Promise<{ isFile(): boolean }>;
  };
  export function createReadStream(path: string, options?: { highWaterMark?: number }): AsyncIterable<Uint8Array>;
  export function realpathSync(path: string): string;
}

declare module "node:url" {
  export function pathToFileURL(path: string): URL;
}

interface ImportMeta {
  readonly url: string;
}
