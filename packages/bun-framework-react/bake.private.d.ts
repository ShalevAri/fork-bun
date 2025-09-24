/** Module Ids are pre-resolved by the bundler, and should be treated as opaque strings.
 * In practice, these strings are the relative file path to the module. */
type Id = string;

/** Index with same usage as `IncrementalGraph(.client).Index` */
type FileIndex = number;

interface Config {
  // Server + Client
  main: Id;

  // Server
  separateSSRGraph?: true;

  // Client
  /** Bun version */
  bun: string;
  /** Dev Server's `configuration_hash_key` */
  version: string;
  /** If available, this is the Id of `react-refresh/runtime` */
  refresh?: Id | undefined;
  /**
   * A list of "roots" that the client is aware of. This includes
   * the framework entry point, as well as every client component.
   */
  roots: FileIndex[];
  /**
   * If true, the client will receive console logs from the server.
   */
  console: boolean;
  generation: number;
}

/**
 * Set globally in debug builds.
 * Removed using --drop=ASSERT in releases.
 */
declare namespace DEBUG {
  function ASSERT(condition: unknown, message?: string): asserts condition;
}

/** All modules for the initial bundle. */
declare const unloadedModuleRegistry: Record<string, UnloadedModule | true>;
declare type UnloadedModule = UnloadedESM | UnloadedCommonJS;
declare type UnloadedESM = [
  deps: EncodedDependencyArray,
  exportKeys: string[],
  starImports: Id[],
  load: (mod: import("../../src/bake/hmr-module.ts").HMRModule) => Promise<void>,
  isAsync: boolean,
];
declare type EncodedDependencyArray = (string | number)[];
declare type UnloadedCommonJS = (
  hmr: import("../../src/bake/hmr-module.ts").HMRModule,
  module: import("../../src/bake/hmr-module.ts").HMRModule["cjs"],
  exports: unknown,
) => unknown;
declare type CommonJSModule = {
  id: Id;
  exports: any;
  require: (id: Id) => unknown;
};

declare const config: Config;

/**
 * The runtime is bundled for server and client, which influences
 * how HMR connection should be established, as well if there is
 * a window to visually display errors with.
 */
declare const side: "client" | "server";

/*
 * If you are running a debug build of Bun. These debug builds should provide
 * helpful information to someone working on the bundler itself. Assertions
 * aimed for the end user should always be enabled.
 */
declare var IS_BUN_DEVELOPMENT: unknown;

/** If this is the fallback error page */
declare const IS_ERROR_RUNTIME: boolean;

interface Window {
  __bun_f: Array<string | Uint8Array<ArrayBuffer>>;
}

// The following interfaces have been transcribed manually.
declare module "react-server-dom-bun/client.browser" {
  export function createFromReadableStream<T>(readable: ReadableStream<T>): Promise<T>;
}

declare module "react-server-dom-bun/client.node.unbundled.js" {
  import type { SSRManifest } from "bun:app/server";
  import type { Readable } from "node:stream";

  export interface Manifest {
    moduleMap: SSRManifest;
    moduleLoading?: ModuleLoading;
  }

  export interface ModuleLoading {
    prefix: string;
    crossOrigin?: string;
  }

  export interface Options {
    encodeFormAction?: any;
    findSourceMapURL?: any;
    environmentName?: string;
  }

  export function createFromNodeStream<T = any>(readable: Readable, manifest?: Manifest): Promise<T>;
}

declare module "react-server-dom-bun/server.node.unbundled.js" {
  import type { ServerManifest } from "bun:app/server";
  import type { ReactElement } from "react";

  export interface PipeableStream<T> {
    /** Returns the input, which should match the Node.js writable interface */
    pipe: <T extends NodeJS.WritableStream>(destination: T) => T;
    abort: () => void;
  }

  export function renderToPipeableStream<T = any>(
    model: ReactElement,
    webpackMap: ServerManifest,
    options?: RenderToPipeableStreamOptions,
  ): PipeableStream<T>;

  export interface RenderToPipeableStreamOptions {
    onError?: (error: Error) => void;
    identifierPrefix?: string;
    onPostpone?: () => void;
    temporaryReferences?: any;
    environmentName?: string;
    filterStackFrame?: () => boolean;
  }
}

declare module "react-dom/server.node" {
  export * from "react-dom/server";
}

declare module "bun:wrap" {
  export const __name: unknown;
  export const __legacyDecorateClassTS: unknown;
  export const __legacyDecorateParamTS: unknown;
  export const __legacyMetadataTS: unknown;
  export const __using: unknown;
  export const __callDispose: unknown;
}
