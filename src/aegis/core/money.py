"""Money value object: exact decimal arithmetic for financial actions.

The BFSI path must never use binary floats (or bare `int` whole units) for
money. `Money` wraps `decimal.Decimal` in minor units (cents) so comparison,
addition, and contract bounds are exact and currency-aware.

    Money.from_minor(4500000, "USD")   # $45,000.00
    Money(Decimal("45000.00"), "USD")  # same value
    money > Money.from_minor(5000000, "USD")  # False (below $50k cap)

`Money` is immutable and hashable, so it can be used as a contract-bound
parameter value directly.
"""
from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, InvalidOperation, ROUND_HALF_EVEN

# ISO 4217 minor-unit exponents (0 = no decimals, 2 = cents, 3 = millimes).
MINOR_UNITS = {"USD": 2, "EUR": 2, "GBP": 2, "JPY": 0, "BHD": 3, "KWD": 3}


@dataclass(frozen=True)
class Money:
    amount: Decimal
    currency: str = "USD"

    def __post_init__(self) -> None:
        if not isinstance(self.amount, Decimal):
            object.__setattr__(self, "amount", Decimal(str(self.amount)))
        if self.currency not in MINOR_UNITS:
            raise ValueError(f"unsupported currency {self.currency!r}")

    # -- constructors ----------------------------------------------------
    @classmethod
    def from_minor(cls, minor_units: int, currency: str = "USD") -> "Money":
        """Build from integer minor units (cents), the only safe wire form."""
        exp = MINOR_UNITS[currency]
        return cls(Decimal(minor_units).scaleb(-exp), currency)

    @classmethod
    def parse(cls, text: str, currency: str = "USD") -> "Money":
        """Parse a human/decimal string ('4,500,000.00') exactly."""
        try:
            return cls(Decimal(text.replace(",", "")), currency)
        except InvalidOperation as exc:
            raise ValueError(f"invalid money amount {text!r}") from exc

    # -- arithmetic ------------------------------------------------------
    def __add__(self, other: "Money") -> "Money":
        self._check_currency(other)
        return Money(self.amount + other.amount, self.currency)

    def __sub__(self, other: "Money") -> "Money":
        self._check_currency(other)
        return Money(self.amount - other.amount, self.currency)

    def __neg__(self) -> "Money":
        return Money(-self.amount, self.currency)

    def _check_currency(self, other: "Money") -> None:
        if self.currency != other.currency:
            raise ValueError(
                f"currency mismatch: {self.currency} vs {other.currency}")

    # -- comparison ------------------------------------------------------
    def __lt__(self, other: "Money") -> bool:
        self._check_currency(other)
        return self.amount < other.amount

    def __le__(self, other: "Money") -> bool:
        self._check_currency(other)
        return self.amount <= other.amount

    def __gt__(self, other: "Money") -> bool:
        self._check_currency(other)
        return self.amount > other.amount

    def __ge__(self, other: "Money") -> bool:
        self._check_currency(other)
        return self.amount >= other.amount

    # -- serialization ---------------------------------------------------
    def to_minor(self) -> int:
        """Exact integer minor units for wire/storage (never a float)."""
        exp = MINOR_UNITS[self.currency]
        return int((self.amount * (Decimal(10) ** exp)).to_integral_value(
            rounding=ROUND_HALF_EVEN))

    def __str__(self) -> str:
        return f"{self.amount:.{MINOR_UNITS[self.currency]}f} {self.currency}"


__all__ = ["MINOR_UNITS", "Money"]
