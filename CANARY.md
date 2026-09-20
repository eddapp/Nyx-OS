# NyxOS Warrant Canary

**Statement date:** 2026-09-20
**Next statement due:** 2026-12-20 (a canary older than this is expired and must be treated as a warning)
**Covers:** the NyxOS source repository, its package repository, and every ISO built from it

As of the statement date above, the NyxOS maintainers declare that:

1. We have received no warrants, subpoenas, National Security Letters, gag orders, or other legal demands for user information, source code, or signing keys.
2. We have not been asked or compelled by any party to insert a backdoor, weaken cryptography, alter routing/DNS/kill-switch behaviour, or ship any covert change in NyxOS.
3. The NyxOS build-signing key has not, to our knowledge, been lost, seized, or compromised.
4. No NyxOS release has been modified by a third party between build and publication.

NyxOS collects no telemetry and operates no accounts, so there is no user data to demand; this canary exists to cover the build and signing chain, which is the only thing a compelled maintainer could be forced to subvert.

## How this canary is published

- The current statement is this file at the root of the source tree.
- Every ISO build signs it with the NyxOS build-signing key and ships it on the image as `/usr/share/nyxos/CANARY.md` with a detached signature `CANARY.md.asc` and the public key `nyxos-build-signing-key.asc` beside it.
- The signed build manifest written next to each ISO records the canary's SHA-256, binding the exact statement to that image.

## How to verify

```
gpg --import /usr/share/nyxos/nyxos-build-signing-key.asc
gpg --verify /usr/share/nyxos/CANARY.md.asc /usr/share/nyxos/CANARY.md
```

Then check three things by hand: the statement date has not passed its due date, the key fingerprint matches the one published with the ISO manifest, and every numbered statement above is still present. A missing, unsigned, or expired canary means you should not trust the build until a fresh one is published.
