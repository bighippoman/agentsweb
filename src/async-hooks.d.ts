// Minimal ambient typing for node:async_hooks. The runtime implementation is
// provided by the Cloudflare Workers `nodejs_compat` flag (see wrangler.toml),
// but @cloudflare/workers-types doesn't ship these declarations and we don't want
// to pull in all of @types/node (it clashes with the Workers globals).
//
// This is a standalone .d.ts (not a module file), so `declare module` here is an
// AMBIENT module declaration — required to type the `node:async_hooks` import.
// It MUST be committed alongside src/index.ts or the `tsc --noEmit` predeploy
// gate will fail on a clean checkout.
declare module "node:async_hooks" {
  export class AsyncLocalStorage<T> {
    getStore(): T | undefined;
    run<R>(store: T, callback: () => R): R;
    run<R, A extends unknown[]>(store: T, callback: (...args: A) => R, ...args: A): R;
    enterWith(store: T): void;
    disable(): void;
  }
}
