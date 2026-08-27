# bb-hook

This repository contains a safe, no-op `post-checkout` hook fixture.

The hook must not read or persist host data, account information, environment
variables, credentials, tokens, or other process secrets. In particular, a
checkout hook runs outside the application's TLS boundary, so collecting that
data would be a separate local sensitive-data exposure rather than evidence of
impact from a remote certificate hostname mismatch.

## Verification

Run the following checks from the repository root:

```sh
sh -n y/hooks/post-checkout
tmpdir="$(mktemp -d)"
(
  cd "$tmpdir"
  /workspace/bb-hook/y/hooks/post-checkout old-ref new-ref 1
)
test -z "$(find "$tmpdir" -mindepth 1 -print -quit)"
rm -rf "$tmpdir"
```
