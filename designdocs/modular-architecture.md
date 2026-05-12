# Migration to a more modular bitcoinj architecture

Note: Packages that are not significant or are not changing are not shown (and are generally expected to remain in the `core` module/JAR).

Legend: Dashed lines represent Gradle "implementation" dependencies. Solid lines represent Gradle "api" dependencies (or internal package dependencies.)

## bitcoinj 0.16 (November 2021)

````mermaid
flowchart TD
    E[examples] --> CORE
    T[tools] --> CORE
    FX[wallettemplate] --> CORE
    subgraph CORE [bitcoinj-core]
        W[o.b.wallet] --> CO
        W --> CR
        CO[o.b.core] --> CR
        CO --> W
        CR[o.b.crypto] --> CO
        CR --> W
    end
    CORE --> G[Guava]
    CORE --> BC[Bouncy Castle]
    CORE --> P[ProtoBuf]
    CORE .-> S[SLF4J]
    CORE .-> A[jcip-annotations]

classDef external fill:#999;
class G,S,A,BC,P external;
````
           
## bitcoinj 0.17 (February 2025)

In release 0.17 there was significant refactoring to prepare the `o.b.base` package to become an independent module/JAR in 0.18. `base` still contains some deprecated methods that depend on `o.b.core`. In 0.18, `base` is moved to its own module and those deprecated methods are removed.


````mermaid
flowchart TD
    E[examples] --> CORE
    IT[integration-test] --> CORE
    T[tools] --> CORE
    FX[wallettemplate] --> CORE
    WT[wallettool] --> CORE
    subgraph CORE [bitcoinj-core]
        W[o.b.wallet] --> CO[o.b.core]
        CO --> W
        W --> CR
        CO --> CR
        CO --> B[o.b.base]
        CR[o.b.crypto] --> B
    end
    CORE --> G[Guava]
    CORE --> P[ProtoBuf]
    CORE --> BC[Bouncy Castle]
    CORE .-> S[SLF4J]
    CORE .-> A[jcip-annotations]

classDef external fill:#999;
class G,S,A,BC,P external;
````

## bitcoinj 0.18 (current plan)

* The `bitcoinj-base` is now a standalone module with a single, small external dependency: **JSpecify** (for nullability annotations.)
* All usage of jcip-annotations is replaced by **JSpecify**. All modules and packages will be `@NullMarked` (meaning all parameters and return types are non-nullable by default.)
* All usage of Google's **Guava** library will be eliminated.

````mermaid
flowchart TD
    EJ[examples] --> CORE
    EK[examples-kotlin] --> CORE
    IT[integration-test] --> CORE
    T[tools] --> CORE
    FX[wallettemplate] --> CORE
    WT[wallettool] --> CORE
    subgraph CORE [bitcoinj-core]
        CO --> W
        W[o.b.wallet] --> CO[o.b.core]
        W --> CR[o.b.crypto]
        CO --> CR
    end
    CORE --> BASE
    subgraph BASE [bitcoinj-base]
        B[o.b.base]
    end
    CORE --> BC[Bouncy Castle]
    CORE --> P[ProtoBuf]
    CORE .-> S[SLF4J]
    BASE --> JS[JSpecify]

classDef external fill:#999;
class G,S,JS,BC,SECPC,P external;
````

## bitcoinj 0.19 (proposed)

In this release all use of Elliptic Curve Cryptography will be refactored to use the `secp-api` module from [secp256k1-jdk](https://github.com/bitcoinj/secp256k1-jdk) with API implementations provided for **Bouncy Castle** and the [secp256k1](https://github.com/bitcoin-core/secp256k1) native ('C') library.

We will also do some preliminary work to further decouple the `o.b.wallet` module from `o.b.core` in preparation for release 0.20.

````mermaid
flowchart TD
    EJ[examples] --> CORE
    EK[examples-kotlin] --> CORE
    IT[integration-test] --> CORE
    T[tools] --> CORE
    FX[wallettemplate] --> CORE
    WT[wallettool] --> CORE
    subgraph CORE [bitcoinj-core]
        CO .-> W
        W[o.b.wallet] --> CO[o.b.core]
        W --> CR[o.b.crypto]
        CO --> CR
    end
    CORE --> BASE
    subgraph BASE [bitcoinj-base]
        B[o.b.base]
    end
    CORE --> SECP[secp-api]
    SECP .-> SECPBC[secp-bouncy]
    SECP .-> SECPFFM[secp-ffm]
    SECPBC --> BC[Bouncy Castle]
    SECPFFM --> SECPC[libsecp256k1]
    CORE --> P[ProtoBuf]
    CORE .-> S[SLF4J]
    BASE --> JS[JSpecify]

classDef external fill:#999;
class G,S,JS,BC,SECPC,P external;
````

## bitcoinj 0.20 (proposed)

In a proposed 0.20 release, we hope to do the following:

1. Separate the current ProtoBuf-based wallet implementation into its own module. This will require creating a `Wallet` interface in core.

Stretch goal:

3. Alternate wallet implementation, perhaps using **SQLite**.


````mermaid
flowchart TD
    E[examples] --> WALLET
    EK[examples-kotlin] --> WALLET
    IT[integration-test] --> WALLET
    T[tools] --> WALLET
    FX[wallettemplate] --> WALLET
    WT[wallettool] --> WALLET
    subgraph WALLET [bitcoinj-wallet-protobuf]
        W[o.b.wallet]
    end
    WALLET --> CORE
    WALLET --> P[ProtoBuf]
    subgraph CORE [bitcoinj-core]
        CO[o.b.core] --> CR[o.b.crypto]
    end
    CORE --> BASE
    CORE --> SECP
    CORE .-> S[SLF4J]
    BASE --> JS[JSpecify]
    SECP[secp-api] .-> SECPFFM[secp-ffm]
    SECP .-> SECPBOUNCY[secp-bouncy]
    SECPBOUNCY .-> BC[Bouncy Castle]
    SECPFFM .-> LP[libsecp256k1]
    subgraph BASE [bitcoinj-base]
        B[o.b.base]
    end

classDef external fill:#999;
class G,S,JS,BC,LP,P external;
````
