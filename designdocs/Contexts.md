# Design of API contexts

This design doc describes the Context class that is new in 0.13.

## Goals

- To centralise various bits of configuration that are presently duplicated throughout the API, such as directories for
  storing files, the depth at which a tx is considered un-reorgable, the chosen network parameters and so on.
- To simplify bitcoinj programming in future.
- To avoid the temptation to overload NetworkParameters with tweakable bits and pieces of misc configuration.
- Unblock various bits of API evolution that are currently made difficult by the desire to avoid too many source code
  changes by developers.

## Background

Since the very first version bitcoinj has had the concept of "network parameters": a class that wrapped various
constants and magic numbers that distinguish the Bitcoin main network from the test network, and later, from settings
meant only for unit tests and local regression testing.

However unlike many APIs, we have never had a more general notion of context and as the library has grown we have
ended up with an often confusing mishmash of duplicate settings and odd dependencies between objects. For example
several parts of the library want to throw away data once a transaction is confirmed enough that we don't expect it
to ever be re-orgd out of the chain, but there's no agreement on how deep that should be. The Wallet stores files, as
does the block store, as does Orchid (Tor support), but each component must be told where to put this data individually.
The problem gets worse on Android, where there are no JAR files and data must be shipped as external files. On this
platform components that want to load data files must be configured with a path to their files individually and
there's no central list of what components need this.

Another problem is that in a few places, we have APIs that are in wide usage but need to start accepting an explicit
component to allow the underlying code to evolve. Top of the list is TransactionConfidence. Consider
TransactionConfidence.getDepthInBlocks(). This method takes no parameters and thus practically requires that the
confidence object for every transaction in a wallet be touched on every single block in order to update its internal
counter. A better approach would be for it to just record the height it appeared at and then take an AbstractBlockChain
as a parameter (and/or explicit height) then do the subtraction. But often this method is called in places far away
from the last reference to a block chain and so this will be a painful API change. Ideally we could spread it out over
a release or two, to give developers time to update their code.

An even bigger issue is Transaction.getConfidence() itself. We would like to rewrite the Wallet so it no longer stores
Transaction objects at all. But this would be a major API break, because apps often want to know about the confidence
of a transaction and currently the only way to obtain this is via the getConfidence() method. The TxConfidenceTable class
(renamed from MemoryPool) acts as a global map of txhash to confidence object, but we can't adjust the prototype of
Transaction.getConfidence() to take one without breaking lots of code.

This proliferation of global variables makes it harder for developers to use multiple instances of bitcoinj
simultaneously, for example, to do cross-chain trading of different cryptocurrencies against each other.

Finally, several bitcoinj objects currently need to be plugged together in ways that aren't always obvious for full
functionality to work. The constructors try to guide the developer but it's still a common source of mistakes.

We can resolve these problems by introducing a notion of a global Context object, used in the same places and ways as
NetworkParameters is today.

## Context object

The Context class is very simple. It is an immutable class that simply holds configuration data and references to other
objects. For now, we do not allow on-the-fly reconfiguration of the data stored within it. This is to simplify the
implementation code.

## Alternatives considered

Some code bases, when faced with similar problems to the above, use a dependency injection container. These pieces
of software effectively replace the "new" keyword and handle all object creation themselves, then wire objects together
based on annotations and centralised, explicit configuration.

Dependency injection would seem to be an attractive solution, but:

* Experience of using Guice inside Google leads me to believe it will result in confusing code that breaks IDE navigation
  features and is hostile to the inexperienced code reader.
* Guice effectively changes the Java language and that makes it harder for people to contribute. There may be DI
  frameworks that are less aggressive, but I don't know of any.
* DI often relies heavily on reflection and even runtime code synthesis, which we wish to avoid for performance reasons
  and to avoid complicating ProGuard configuration and transpilation.
* DI is effectively just a complicated and indirect means of having a global context object: doing it directly makes the
  code clearer and avoids the need for developers to learn new things.

## Transition plan

NetworkParameters appears everywhere in the bitcoinj API, and so introducing Context will have a major impact on it
as well. We aim to keep API churn under control, to avoid losing developers across difficult upgrades. As such,
Context will be phased in gradually over one or two releases.

We will follow these stages:

1. Context starts out by wrapping NetworkParameters, TxConfidenceTable and the "event horizon" (the number of blocks
   after which we assume re-orgs cannot happen).
2. The construction of a Context object puts a reference to itself into a thread local storage slot. A static method
   is provided which retrieves this, as well as another that either retrieves _or creates_ a new Context. This second
   method is placed in the constructors of key classes like the Wallet or the block chain, and provides backwards
   compatibility for developers. A log message is printed advising developers to update their code to create a Context
   themselves. Attempting to use two instances of the library with different objects or NetworkParameters from the same
   thread may have complications or not work properly during this stage.
3. Classes that currently take NetworkParameters are augmented with new constructors that take Contexts instead. The
   old c'tors simply check the NetworkParameters they are given matches the Context's own view and then call into the
   new c'tors. An exception is thrown if they don't match.
4. Release notes describe how to set a context and propagate it between threads. Developers can start migration in the
   0.13 release.
5. Internally, we start passing contexts through to objects that want one explicitly rather than relying on the thread
   local storage slot.
6. We mark constructors that take NetworkParameters as deprecated with the javadocs changing to point devs to the
   Context-taking equivalents.
7. In some future release, the deprecated methods are eventually removed, along with the Context thread local storage
   slot and automated cross-thread propagation magic.

In parallel, global configuration will keep being moved into the Context class to make it more useful.