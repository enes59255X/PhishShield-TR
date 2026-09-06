"""
Learning System - PhishShield TR V3

Collects analysis data, manages datasets, handles feedback, and trains models.
"""

from learning.collector import LearningCollector, LearningSample, SampleLabel
from learning.dataset import DatasetManager, DatasetEntry
from learning.feedback import FeedbackHandler, FeedbackEntry, FeedbackType
from learning.trainer import ModelTrainer, TrainingConfig, TrainingResult

__all__ = [
    "LearningCollector",
    "LearningSample", 
    "SampleLabel",
    "DatasetManager",
    "DatasetEntry",
    "FeedbackHandler",
    "FeedbackEntry",
    "FeedbackType",
    "ModelTrainer",
    "TrainingConfig",
    "TrainingResult",
]
