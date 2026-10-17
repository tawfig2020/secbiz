"""QKD simulation (Pillar 5): BB84 key exchange with intercept detection.

EDUCATIONAL MODULE — NOT a production key-establishment mechanism. It models
the statistics of BB84 (basis matching, QBER, intercept detection) for the
demo narrative. It is deliberately seedable and non-cryptographic.

For production, BFSI buyers ask about post-quantum cryptography (PQC), not
QKD. The production key-establishment seam lives in
`aegis.core.asymmetric.PqcKeyExchange` / `PqcKem` (ML-KEM/Kyber via
liboqs-python). QKD requires photonic hardware and trusted relays that are
out of scope for this reference implementation.

Alice sends qubits in random bases; Bob measures in random bases. Sifted key
= positions where bases matched. An eavesdropper (Eve) must guess a basis to
measure -- a wrong guess collapses the photon state and injects a 25% error
rate into the sifted key. If QBER > threshold, the exchange aborts and keys
rotate -- the quantum channel itself raises the alarm.

SIMULATION ONLY: bits come from a seedable, non-cryptographic PRNG, so the
output must never be used as real key material.
"""
from __future__ import annotations

import random
from dataclasses import dataclass


@dataclass(frozen=True)
class QKDResult:
    exchanged: int
    sifted_length: int
    qber: float                     # quantum bit error rate
    eavesdropper_detected: bool
    key_established: bool
    key_preview: str                # first 32 bits, never the full key


def simulate_bb84(n_qubits: int = 1024, eavesdropper: bool = False,
                  sample_fraction: float = 0.5, threshold: float = 0.11,
                  seed: int = 7) -> QKDResult:
    rng = random.Random(seed)

    alice_bits = [rng.getrandbits(1) for _ in range(n_qubits)]
    alice_bases = [rng.getrandbits(1) for _ in range(n_qubits)]
    bob_bases = [rng.getrandbits(1) for _ in range(n_qubits)]

    channel_bits = list(alice_bits)
    if eavesdropper:
        # Eve measures in a random basis; wrong basis collapses the state
        # and re-randomizes the bit Bob receives.
        eve_bases = [rng.getrandbits(1) for _ in range(n_qubits)]
        channel_bits = [
            bit if eb == ab else rng.getrandbits(1)
            for bit, eb, ab in zip(channel_bits, eve_bases, alice_bases)
        ]

    # Bob measures; matching basis -> same bit, mismatched basis discarded.
    sifted_alice, sifted_bob = [], []
    for i in range(n_qubits):
        if alice_bases[i] == bob_bases[i]:
            sifted_alice.append(alice_bits[i])
            sifted_bob.append(channel_bits[i])

    # QBER estimated on a public subset of the sifted key.
    n_sample = max(1, int(len(sifted_alice) * sample_fraction))
    errors = sum(1 for a, b in zip(sifted_alice[:n_sample],
                                 sifted_bob[:n_sample]) if a != b)
    qber = errors / n_sample

    # Detection must depend only on what the parties can observe (QBER),
    # never on the simulation's hidden `eavesdropper` ground truth.
    detected = qber > threshold
    # Sampled bits were disclosed publicly: they are discarded from the key.
    final_key = sifted_alice[n_sample:]
    established = qber <= threshold and len(final_key) >= 64

    preview = "".join(map(str, final_key[:32])) if established else "(aborted)"
    return QKDResult(
        exchanged=n_qubits,
        sifted_length=len(sifted_alice),
        qber=round(qber, 4),
        eavesdropper_detected=detected,
        key_established=established,
        key_preview=preview,
    )
