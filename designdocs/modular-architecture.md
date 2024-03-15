# Overview of our migration plans to a more modular bitcoinj architecture

Note: Packages that are not significant or are not changing are not shown (and are generally expected to remain in the `core` module/JAR).

Legend: Dashed lines represent Gradle "implementation" dependencies. Solid lines represent Gradle "api" dependencies (or internal package dependencies.)

## bitcoinj 0.16.x (current stable release)

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
    CORE .-> S[slf4j]
    CORE .-> A[jcip-annotations]

classDef external fill:#999;
class G,S,A,BC,P external;
````
           
## bitcoinj 0.17 (current plan)

In release 0.17 (currently in progress) there has been a large amount of refactoring to prepare the `o.b.base` and `o.b.crypto` packages to become independent modules/JARs in the following release. Those packages will still contain some deprecated methods that depend on other internal packages and external modules. Those deprecated methods will be removed in release 0.18 when `o.b.base` and `o.b.crypto` are moved to their own modules.


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
    CORE .-> S[slf4j]
    CORE .-> A[jcip-annotations]

classDef external fill:#999;
class G,S,A,BC,P external;
````

## bitcoinj 0.18 (current plan)
 
In this release it will be possible to use the `bitcoinj-base` module as a standalone module with no external dependencies. `bitcoinj-crypto` will be able to be used with a single dependency on the **Bouncy Castle*** library.

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
    end
    CORE --> CRYPTO
    subgraph CRYPTO [bitcoinj-crypto]
        CR[o.b.crypto]
    end
    CRYPTO --> BASE
    CRYPTO --> BC[Bouncy Castle]
    subgraph BASE [bitcoinj-base]
        B[o.b.base]
    end
    CORE --> G[Guava]
    CORE --> P[ProtoBuf]
    CORE .-> S[slf4j]
    CORE .-> A[jcip-annotations]

classDef external fill:#999;
class G,S,A,BC,P external;
````

## bitcoinj 0.19 (proposed)

In a proposed 0.19 release, we hope to do the following:

1. Update `bitcoin-crypto` to use the `secp256k1-jdk` API so that core crypto functions that it needs can be provided by either Bouncy Castle _or_ `libsecp256k1`.
2. Separate the current ProtoBuf-based wallet implementation into it's own module. This will require creating a `Wallet` interface in core.
3. Eliminate dependencies on Guava for all modules.

Stretch goal:

4. Alternate wallet implementation, perhaps using **SQLite**.


````mermaid
flowchart TD
    E[examples] --> WALLET
    IT[integration-test] --> WALLET
    T[tools] --> WALLET
    FX[wallettemplate] --> WALLET
    WT[wallettool] --> WALLET
    subgraph WALLET [bitcoinj-wallet-protobuf]
        W[o.b.wallet]
    end
    WALLET --> CORE
    WALLET .-> S[slf4j]
    WALLET --> P[ProtoBuf]
    subgraph CORE [bitcoinj-core]
        CO[o.b.core]
    end
    CORE --> CRYPTO
    CORE .-> S[slf4j]
    subgraph CRYPTO [bitcoinj-crypto]
        CR[o.b.crypto]
    end
    CRYPTO --> BASE
    CRYPTO --> SECP256K1
    SECP256K1[secp256k1-jdk] .-> SECPFFM[secp256k1-foreign]
    SECP256K1[secp256k1-jdk] .-> SECPBOUNCY[secp256k1-bouncy]
    SECPBOUNCY .-> BC[Bouncy Castle]
    SECPFFM .-> LP['C' libsecp256k1]
    subgraph BASE [bitcoinj-base]
        B[o.b.base]
    end

classDef external fill:#999;
class G,S,A,BC,LP,P external;
````
