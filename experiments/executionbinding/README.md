# Resource and lease contract experiment

Run `go test ./experiments/executionbinding -count=1 -v`.

This test-only package is not linked into the server. It compares an action-only writer with a writer that atomically checks controller-signed object and lease versions before mutating an in-memory object. It provides eight negative comparisons, a valid write, replay/tampering rejection, and 32 competing writes.

It does not implement the actual Permit codec, a remote broker, filesystem writes, Docker/VM isolation, or attestation. See the [implementation record](../../docs/prepared-execution.md) and [中文记录](../../docs/prepared-execution.zh-CN.md) for results and integration limits.
