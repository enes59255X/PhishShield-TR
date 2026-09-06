"""
PhishShield TR - Analysis Module
Signal-based analysis coordinator
"""

from analysis.analyzer import (
    analyze_url,
    analyze_url_legacy,
    run_new_analysis,
    SignalExtractor
)

__all__ = [
    "analyze_url",
    "analyze_url_legacy", 
    "run_new_analysis",
    "SignalExtractor"
]
