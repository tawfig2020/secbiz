"""Core Platform + Verticalized Modules + compliance-tiered packaging."""
from .loader import (
    RegexDetector,
    load_vertical_json,
    load_vertical_policy,
    register_detector,
    vertical_from_dict,
)
from .pack import ComplianceControl, VerticalPack
from .bfsi import (
    SwiftManipulationDetector,
    TRANSACTION_CONTRACT,
    bfsi_pack,
)
from .healthcare import (
    CLINICAL_CONTRACT,
    PhiExfiltrationDetector,
    healthcare_pack,
)
from .government import (
    ClassifiedTaintDetector,
    RECORDS_CONTRACT,
    government_pack,
)

# Built-in detectors are addressable by name from a declarative policy file.
register_detector("swift_manipulation", SwiftManipulationDetector)
register_detector("phi_exfiltration", PhiExfiltrationDetector)
register_detector("classified_taint", ClassifiedTaintDetector)

_PACK_FACTORIES = {
    "bfsi": bfsi_pack,
    "healthcare": healthcare_pack,
    "government": government_pack,
}


def available_packs() -> tuple[str, ...]:
    return tuple(_PACK_FACTORIES)


def load_pack(name: str) -> VerticalPack:
    """Factory lookup: load_pack("bfsi") -> the BFSI vertical module."""
    factory = _PACK_FACTORIES.get(name.lower())
    if factory is None:
        raise KeyError(
            f"unknown pack {name!r}; available: {sorted(_PACK_FACTORIES)}")
    return factory()


__all__ = [
    "CLINICAL_CONTRACT",
    "ClassifiedTaintDetector",
    "ComplianceControl",
    "PhiExfiltrationDetector",
    "RECORDS_CONTRACT",
    "RegexDetector",
    "SwiftManipulationDetector",
    "TRANSACTION_CONTRACT",
    "VerticalPack",
    "available_packs",
    "bfsi_pack",
    "government_pack",
    "healthcare_pack",
    "load_pack",
    "load_vertical_json",
    "load_vertical_policy",
    "register_detector",
    "vertical_from_dict",
]
