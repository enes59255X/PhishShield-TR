"""
PhishShield TR - Detection Module
Signal-based threat detection with correlation engine
"""

from detection.signals import (
    SignalSeverity,
    ThreatCategory,
    SIGNAL_DEFINITIONS,
    get_signal_weight,
    get_signal_severity,
    is_critical_signal,
    is_high_signal,
    is_informational_signal
)

from detection.correlation import (
    CorrelationEngine,
    CorrelationRule,
    calculate_signal_score
)

from detection.decision import (
    Decision,
    DecisionResult,
    DecisionEngine,
    make_final_decision,
    RISK_THRESHOLDS
)

from detection.explanation import (
    generate_explanation,
    format_popup_response,
    generate_technical_report,
    EMOJI_MAP,
    DECISION_TEXT,
    DECISION_DESCRIPTIONS
)

from detection.result import (
    CanonicalResult,
    DecisionInfo,
    SiteInfo,
    Flags,
    Summary,
    normalize_result,
    create_safe_result,
    create_danger_result,
    create_caution_result
)

__all__ = [
    # Signals
    "SignalSeverity",
    "ThreatCategory",
    "SIGNAL_DEFINITIONS",
    "get_signal_weight",
    "get_signal_severity",
    "is_critical_signal",
    "is_high_signal",
    "is_informational_signal",
    
    # Correlation
    "CorrelationEngine",
    "CorrelationRule",
    "calculate_signal_score",
    
    # Decision
    "Decision",
    "DecisionResult",
    "DecisionEngine",
    "make_final_decision",
    "RISK_THRESHOLDS",
    
    # Explanation
    "generate_explanation",
    "format_popup_response",
    "generate_technical_report",
    "EMOJI_MAP",
    "DECISION_TEXT",
    "DECISION_DESCRIPTIONS",
    
    # Result (NEW - Phase 1)
    "CanonicalResult",
    "DecisionInfo",
    "SiteInfo",
    "Flags",
    "Summary",
    "normalize_result",
    "create_safe_result",
    "create_danger_result",
    "create_caution_result"
]
