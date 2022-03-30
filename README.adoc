image:https://github.com/bitcoinj/bitcoinj/workflows/Java%20CI/badge.svg[GitHub Build Status,link=https://github.com/bitcoinj/bitcoinj/actions]
image:https://gitlab.com/bitcoinj/bitcoinj/badges/master/pipeline.svg[GitLab Build Status,link=https://gitlab.com/bitcoinj/bitcoinj/pipelines]
image:https://coveralls.io/repos/bitcoinj/bitcoinj/badge.png?branch=master[Coverage Status,link=https://coveralls.io/r/bitcoinj/bitcoinj?branch=master]

image::https://kiwiirc.com/buttons/irc.freenode.net/bitcoinj.png[Visit our IRC channel,link=https://kiwiirc.com/client/irc.freenode.net/bitcoinj]

### Welcome to bitcoinj

The bitcoinj library is a Java implementation of the Bitcoin protocol, which allows it to maintain a wallet and send/receive transactions without needing a local copy of Bitcoin Core. It comes with full documentation and some example apps showing how to use it.

### Technologies

* Java 8+ (needs Java 8 API or Android 7.0 API, compiles to Java 8 bytecode) and Gradle 4.4+ for the `core` module
* Java 11+ and Gradle 4.4+ for `tools`, `wallettool` and `examples`
* Java 11+ and Gradle 4.10+ for the JavaFX-based `wallettemplate`
* https://gradle.org/[Gradle] - for building the project
* https://github.com/google/protobuf[Google Protocol Buffers] - for use with serialization and hardware communications

### Getting started

To get started, it is best to have the latest JDK and Gradle installed. The HEAD of the `master` branch contains the latest development code and various production releases are provided on feature branches.

#### Building from the command line

Official builds are currently using JDK 11. Our GitHub Actions build and test with JDK 11 and JDK 17.

To perform a full build (_including_ JavaDocs and unit/integration _tests_) use JDK 11+.

```
gradle clean build
```
If you are using Gradle 4.10 or later, the build will automatically include the JavaFX-based `wallettemplate` module. The outputs are under the `build` directory.

To perform a full build _without_ unit/integration _tests_ use:
```
gradle clean assemble
```

#### Building from an IDE

Alternatively, just import the project using your IDE. http://www.jetbrains.com/idea/download/[IntelliJ] has Gradle integration built-in and has a free Community Edition. Simply use `File | New | Project from Existing Sources` and locate the `build.gradle` in the root of the cloned project source tree.

### Building and Using the Wallet Tool

The *bitcoinj* `wallettool` subproject includes a command-line Wallet Tool (`wallet-tool`) that can be used to create and manage *bitcoinj*-based wallets (both the HD keychain and SPV blockchain state.) Using `wallet-tool` on Bitcoin's test net is a great way to learn about Bitcoin and *bitcoinj*.

To build an executable shell script that runs the command-line Wallet Tool, use:
```
gradle bitcoinj-wallettool:installDist
```

You can now run the `wallet-tool` without parameters to get help on its operation:
```
./wallettool/build/install/wallet-tool/bin/wallet-tool
```

To create a test net wallet file in `~/bitcoinj/bitcoinj-test.wallet`, you would use:
```
mkdir ~/bitcoinj
```
```
./wallettool/build/install/wallet-tool/bin/wallet-tool --net=TEST --wallet=$HOME/bitcoinj/bitcoinj-test.wallet create
```

To sync the newly created wallet in `~/bitcoinj/bitcoinj-test.wallet` with the test net, you would use:
```
./wallettool/build/install/wallet-tool/bin/wallet-tool --net=TEST --wallet=$HOME/bitcoinj/bitcoinj-test.wallet sync
```

To dump the state of the wallet in `~/bitcoinj/bitcoinj-test.wallet` with the test net, you would use:
```
./wallettool/build/install/wallet-tool/bin/wallet-tool --net=TEST --wallet=$HOME/bitcoinj/bitcoinj-test.wallet dump
```

NOTE: These instructions are for macOS/Linux, for Windows use the `wallettool/build/install/wallet-tool/bin/wallet-tool.bat` batch file with the equivalent Windows command-line commands and options.

### Example applications

These are found in the `examples` module.

### Where next?

Now you are ready to https://bitcoinj.github.io/getting-started[follow the tutorial].

### Testing a SNAPSHOT build

Building apps with official releases of *bitcoinj* is covered in the https://bitcoinj.github.io/getting-started[tutorial].

If you want to develop or test your app with a https://jitpack.io[Jitpack]-powered build of the latest `master` or `release-0.15` branch of *bitcoinj* follow the dynamically-generated instructions for that branch by following the correct link.

* https://jitpack.io/#bitcoinj/bitcoinj/master-SNAPSHOT[master] branch
* https://jitpack.io/#bitcoinj/bitcoinj/release-0.15-SNAPSHOT[release-0.15] branch
