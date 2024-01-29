# ZKT Plonk

*This is a fork of the [Plonk](https://github.com/ZK-Garage/plonk) library from ZK-Garage, modified specially for ZKT protocol*

## About

This library contains a series of modules that can be used to construct ZK-SNARK proofs for ZKT protocol.

The `plonk-core` module is an implementation of the Plonk + Plookup proving system, we reorganized the codebase to 
make it better applied for ZKT protocol. See more details of the modified Protocol in this [paper](https://github.com/ZKTNetwork/papers/blob/main/Advancing%20Blockchain%20Transaction%20Privacy%20and%20Compliance%3A%20Insights%20into%20Innovative%20Engineering%20Practices/paper.md).

The `plonk-hashing` module is set to contain several hashing algorithms, currently only the `poseidon` hash function is implemented.

The `circuits` module contains a set of circuits that ZKT protocol applies, currently only the `withdraw` circuit is implemented.

The `wasm` module contains the wasm bindings for the proving system, which can be used to construct proofs in the frontend.

## Features

This crate includes a variety of features which will briefly be explained below:

- `parallel`: Enables `rayon` and other parallelisation primitives to be used and speed up some of the algorithms used by the crate and it's dependencies.

- `asm`: Enables inline-assembly implementations for some of the internal algorithms and primitives used by the `arkworks` dependencies of the crate.

- `trace`: Enables the Circuit debugger tooling. This is essentially the capability of using the `StandardComposer::check_circuit_satisfied` function. The function will output information about each circuit gate until one of the gates does not satisfy the equation, or there are no more gates. If there is an unsatisfied gate equation, the function will panic and return the gate number.

- `trace-print`: Goes a step further than `trace` and prints each `gate` component data, giving a clear overview of all the values which make up the circuit that we're constructing. __The recommended method is to derive the std output, and the std error, and then place them in text file which can be used to efficiently analyse the gates.__

## Performance

TODO

## Acknowledgements

TODO

## Licensing

Mozilla Public License Version 2.0 (MPL-2.0). Please see [LICENSE](https://github.com/ZK-Garage/plonk/blob/master/LICENSE) for further info.
