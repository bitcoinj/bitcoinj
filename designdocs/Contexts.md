# Design of API contexts

This design doc describes the Context class that is new in 0.13.

## Introduction
This document details the new Context class introduced in version 0.13 of the bitcoinj library. The Context class aims to consolidate scattered configuration settings and simplify programming with bitcoinj.

## Goals

- Centralize Configuration: Unify configuration settings such as file storage directories and network parameters that are currently duplicated across the API.
- Simplify Programming: Enhance future development of bitcoinj by centralizing common settings.
- Avoid Overloading: Prevent the misuse of the NetworkParameters class for miscellaneous configuration settings.
- Facilitate API Evolution: Enable smoother updates and modifications to the API without extensive code changes by developers.

## Background

Historically, bitcoinj utilized "network parameters" to differentiate between various network settings. However, as the library evolved, the absence of a general context led to duplications and unclear dependencies among components. For instance, components independently manage file storage, and the depth for irreversible transactions varies without consensus.

Challenges are particularly pronounced on platforms like Android, where the absence of JARs necessitates external file handling, requiring individual component configuration.

Significant issues also arise with the widespread use of certain APIs, such as TransactionConfidence.getDepthInBlocks(), which need modification to better reflect transaction confirmations but currently do not accept parameters, making necessary API changes cumbersome.

## Context object

The Context class is designed to be immutable, storing configuration data and references simplistically, without allowing on-the-fly reconfigurations to maintain simplicity in implementation.

## Alternatives considered

Dependency injection was considered as a solution to manage object creation and configuration. However, it was rejected due to its complexity, the potential to confuse new developers, reliance on heavy reflection, and the fundamental similarity to having a global context object.

## Transition plan

The integration of Context will proceed cautiously to minimize disruption:

Initial Implementation: Context will initially wrap existing classes like NetworkParameters and TxConfidenceTable. It will be stored in thread-local storage for accessibility across different parts of the application.
Incremental Integration: New constructors will accept Context as a parameter, gradually replacing the use of NetworkParameters.
Deprecation: Methods solely using NetworkParameters will be marked deprecated and gradually phased out in favor of methods that use Context.
Full Adoption: By the 0.13 release, developers should start migrating to using Context. Subsequent releases will focus on propagating Context throughout the API without relying on thread-local storage.

## Conclusion
The introduction of the Context class represents a strategic improvement to the bitcoinj library's architecture, simplifying configurations and enhancing the API's robustness and usability.
