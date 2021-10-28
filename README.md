# Welcome to lilbitcoinj

The lilbitcoinj library is a fork of the [bitcoinj project](https://github.com/bitcoinj/bitcoinj/). lilbitcoinj has much less surface area than bitcoinj and keeps the code that is useful for deriving keys and addresses from seeds.

### Getting started

To get started, it is best to have the latest JDK and Gradle installed. The HEAD of the `master` branch contains the latest development code and various production releases are provided on feature branches.

#### Building from the command line

Build with JDK 11

```
gradle clean build
```

To perform a full build *without* unit/integration *tests* use:
```
gradle clean assemble
```

#### Building from an IDE

Alternatively, just import the project using your IDE. [IntelliJ](http://www.jetbrains.com/idea/download/) has Gradle integration built-in and has a free Community Edition. Simply use `File | New | Project from Existing Sources` and locate the `build.gradle` in the root of the cloned project source tree.

