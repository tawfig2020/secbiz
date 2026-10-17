# Aegis Concurrency Model

Aegis runs under `ThreadingHTTPServer` (one thread per request) and must be
safe when many requests interleave. This document records the concurrency
contract for each shared component and the tests that prove it.

## 1. Components and their contracts

| Component | Shared state | Guard | Contract |
| --- | --- | --- | --- |
| `AuditLog` | event list + head hash + SQLite | `threading.Lock` | `record()` is atomic; the hash chain never forks |
| `ReferenceMonitor` | nonce store, attestations, contracts | `threading.RLock` | `evaluate()`/`redeem()`/`delegate()` are serialized |
| `SemanticGateway` | detector per-source state | `threading.RLock` | `scan()` serializes detector state |
| `ApprovalQueue` | SQLite rows | SQLite `UPDATE ... WHERE status='pending'` | two approvers cannot both resolve one item |
| `EventBus` | deque | `threading.Lock` | append/iterate are safe |
| `MetricsRegistry` | counters/gauges/histograms | per-metric `Lock` | increments are atomic |
| `ExecutorAgent` | none (stateless) | n/a | delegates to `ReferenceMonitor.redeem()` |

## 2. The critical race: double execution

The highest-value invariant is **at-most-once execution** of a capability
token (a double wire transfer is irreversible harm).

```text
thread A                          thread B
  executor.execute(token)           executor.execute(token)
    monitor.redeem(token)             monitor.redeem(token)
      with lock:                       with lock:
        verify -> pop nonce -> True      verify -> nonce gone -> False
    run tool  ✓                      refuse  ✗
```

`ReferenceMonitor.redeem()` (`reference_monitor.py`) does verify-and-burn
under one lock, so exactly one caller wins. `ExecutorAgent.execute()` calls
`redeem()` **before** invoking the tool, so side effects happen only after
the token is irreversibly consumed.

## 3. Audit-log interleaving

`AuditLog.record()` holds a lock for the entire
`compute_hash -> INSERT -> append -> advance head` sequence. Two concurrent
writers therefore produce a strictly sequential chain (`seq` is monotonic and
`prev_hash` always points at the immediately preceding event). The
`test_concurrent_records_keep_chain_valid` test (8 threads × 200 events)
asserts the chain verifies and the count is exact.

## 4. Approval-queue TOCTOU

Two approvers resolving the same deferred item is prevented by an atomic
conditional update:

```sql
UPDATE approvals SET status='approved' WHERE id=? AND status='pending'
```

The `rowcount` tells the second approver the item was already resolved. See
`approval_queue.py` and `test_second_pass.py`.

## 5. Event bus is synchronous

`EventBus.emit()` is synchronous and runs on the request path. It is wrapped
in `try/except` at every call site (`gateway._emit`, `monitor._emit`) so a
dashboard failure can never break enforcement. For production, a bounded
in-process queue with a background flusher is the intended upgrade; the
synchronous design is a deliberate fail-safe for the reference build.

## 6. What is NOT yet safe

- **Multi-process**: the nonce store and audit log are in-process (or
  single-node SQLite). Horizontal scaling requires a shared store (Risk B).
- **SQLite write concurrency**: `check_same_thread=False` + a Python lock is
  correct for a single process; it is not a substitute for Postgres under
  multiple replicas.

## 7. Tests

- `tests/test_hardening.py::AuditConcurrencyTests` — audit chain under 8 threads.
- `tests/test_second_pass.py` — approval-queue TOCTOU, executor double-execution.
- `tests/test_concurrency.py` — token redeem race, gateway scan race, metrics
  counter race (added with the observability work).
