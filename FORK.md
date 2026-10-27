# Fork

Upstream: https://github.com/bitcoinj/bitcoinj
Versioning: <upstream-version>-dwdc.<N>

Local patches:
- HD path parsing accepts `h` and `'` hardened suffixes; upstream
  accepts only `H`.
- `toString(char hardeningSymbol)` on `ChildNumber` and `HDPath`.
- BouncyCastle `bcprov-jdk18on` in place of `bcprov-jdk15to18`.

The patches are confined to HD path *parsing and serialization*, not to
derivation arithmetic. A mismatched bitcoinj therefore throws on a
`'`-style path rather than silently deriving different keys.

## Why this fork exists

`keyvault` — and so all of KeyMaster — needs the `h`/`'` hardened-suffix
forms when parsing BIP-32 paths. This fork is not published to any
public repository, so it has to be installed into `~/.m2` by hand before
anything downstream will resolve.

## Building and publishing

Requires **JDK 21**, set explicitly: Gradle 8.13 cannot parse JDK 25
class files, and JDK 25 is the default `java` on current Ubuntu.
Without this you get `Unsupported class file major version 69`.

```sh
export JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
./gradlew publishToMavenLocal
```

That installs both modules, which is required — `core` declares
`api project(':bitcoinj-base')`, so `bitcoinj-base` must exist at the
same version or keyvault's build fails on a missing dependency:

```
~/.m2/repository/org/bitcoinj/bitcoinj-base/0.18-dwdc.1/
~/.m2/repository/org/bitcoinj/bitcoinj-core/0.18-dwdc.1/
```

This is step 1 of the KeyMaster build order; keyvault is step 2. See
[keymaster's README](https://github.com/DarkWebDivingClub/keymaster#build).

## Releasing a new patch level

The version lives in exactly two places, `base/build.gradle` and
`core/build.gradle`. Bump both to the next `-dwdc.<N>`, then commit and
tag with a signed tag:

```sh
git tag -s v0.18-dwdc.<N> -m "bitcoinj 0.18-dwdc.<N>"
git push origin master v0.18-dwdc.<N>
```

Then bump the dependency in `keyvault/club.dwdc.keyvault.core/pom.xml`
and release keyvault, since its dependency set has changed.
