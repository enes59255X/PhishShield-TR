"""
Sprint 13 Learning System Tests
PhishShield TR V3

Tests for:
- LearningCollector
- DatasetManager
- FeedbackHandler
- ModelTrainer
"""

import sys
import os
import time
import tempfile
import shutil

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))


def run_tests():
    print("=" * 60)
    print("Sprint 13 Learning System Tests")
    print("=" * 60)
    
    tests_passed = 0
    tests_failed = 0
    
    temp_dir = tempfile.mkdtemp()
    
    try:
        # Test 1: LearningCollector import
        print("\nTest: LearningCollector import...")
        from learning.collector import LearningCollector, SampleLabel, LearningSample
        print("  PASSED")
        tests_passed += 1
        
        # Test 2: DatasetManager import
        print("\nTest: DatasetManager import...")
        from learning.dataset import DatasetManager, DatasetEntry
        print("  PASSED")
        tests_passed += 1
        
        # Test 3: FeedbackHandler import
        print("\nTest: FeedbackHandler import...")
        from learning.feedback import FeedbackHandler, FeedbackType
        print("  PASSED")
        tests_passed += 1
        
        # Test 4: ModelTrainer import
        print("\nTest: ModelTrainer import...")
        from learning.trainer import ModelTrainer, TrainingConfig
        print("  PASSED")
        tests_passed += 1
        
        # Test 5: LearningCollector basic collection
        print("\nTest: LearningCollector basic collection...")
        collector = LearningCollector(storage_path=os.path.join(temp_dir, "samples.jsonl"))
        
        sample = collector.collect(
            url="https://test-phishing.com/login",
            domain="test-phishing.com",
            features={"has_login_form": True, "external_submit": True},
            risk_score=85,
            ml_probability=0.9,
            final_decision="DANGER",
            source="test"
        )
        
        assert sample.label == "phishing"
        assert sample.risk_score == 85
        print(f"  Collected sample: {sample.label}")
        print("  PASSED")
        tests_passed += 1
        
        # Test 6: LearningCollector safe sample
        print("\nTest: LearningCollector safe sample...")
        safe_sample = collector.collect(
            url="https://google.com",
            domain="google.com",
            features={"has_login_form": False},
            risk_score=10,
            ml_probability=0.05,
            final_decision="SAFE",
            source="test"
        )
        
        assert safe_sample.label == "safe"
        assert safe_sample.risk_score == 10
        print(f"  Safe sample: {safe_sample.label}")
        print("  PASSED")
        tests_passed += 1
        
        # Test 7: LearningCollector stats
        print("\nTest: LearningCollector stats...")
        stats = collector.get_stats()
        assert stats["total_collected"] == 2
        print(f"  Stats: {stats}")
        print("  PASSED")
        tests_passed += 1
        
        # Test 8: FeedbackHandler submission
        print("\nTest: FeedbackHandler submission...")
        feedback_path = os.path.join(temp_dir, "feedback.jsonl")
        handler = FeedbackHandler(storage_path=feedback_path)
        
        fb = handler.submit_feedback(
            url="https://test-phishing.com/login",
            domain="test-phishing.com",
            feedback_type="false_positive",
            original_score=85,
            original_decision="DANGER",
            user_label="safe",
            message="This is my actual bank",
            source="user"
        )
        
        assert fb.feedback_type == "false_positive"
        assert fb.user_label == "safe"
        print(f"  Feedback type: {fb.feedback_type}")
        print("  PASSED")
        tests_passed += 1
        
        # Test 9: FeedbackHandler corrections
        print("\nTest: FeedbackHandler get training corrections...")
        handler.resolve_feedback(fb.url, used_for_training=True)
        
        corrections = handler.get_training_corrections()
        assert len(corrections) == 1
        assert corrections[0]["correct_label"] == "safe"
        print(f"  Corrections: {len(corrections)}")
        print("  PASSED")
        tests_passed += 1
        
        # Test 10: DatasetManager add entry
        print("\nTest: DatasetManager add entry...")
        dataset_path = os.path.join(temp_dir, "dataset.jsonl")
        dm = DatasetManager(dataset_path=dataset_path)
        
        dm.add_entry(
            url="https://phishing-test.com",
            domain="phishing-test.com",
            features={"has_login_form": 1, "external_submit": 1, "suspicious_tld": 1},
            label="phishing",
            source="collector"
        )
        
        dm.add_entry(
            url="https://safe-test.com",
            domain="safe-test.com",
            features={"has_login_form": 0, "external_submit": 0, "suspicious_tld": 0},
            label="safe",
            source="collector"
        )
        
        entries = dm.get_entries()
        assert len(entries) == 2
        print(f"  Entries: {len(entries)}")
        print("  PASSED")
        tests_passed += 1
        
        # Test 11: DatasetManager stats
        print("\nTest: DatasetManager stats...")
        ds_stats = dm.get_stats()
        assert ds_stats["total_entries"] == 2
        assert "phishing" in ds_stats["by_label"]
        assert "safe" in ds_stats["by_label"]
        print(f"  Stats: {ds_stats}")
        print("  PASSED")
        tests_passed += 1
        
        # Test 12: ModelTrainer initialization
        print("\nTest: ModelTrainer initialization...")
        model_dir = os.path.join(temp_dir, "models")
        trainer = ModelTrainer(model_dir=model_dir)
        
        info = trainer.get_model_info()
        print(f"  Model info: {info}")
        print("  PASSED")
        tests_passed += 1
        
        # Test 13: ModelTrainer training
        print("\nTest: ModelTrainer training...")
        training_samples = []
        training_labels = []
        
        for i in range(50):
            training_samples.append({
                "has_login_form": 1,
                "external_submit": 1,
                "suspicious_tld": 1,
                "typo_domain": 1,
                "short_domain": 0,
                "has_ssl": 0
            })
            training_labels.append(1)
        
        for i in range(50):
            training_samples.append({
                "has_login_form": 0,
                "external_submit": 0,
                "suspicious_tld": 0,
                "typo_domain": 0,
                "short_domain": 0,
                "has_ssl": 1
            })
            training_labels.append(0)
        
        config = TrainingConfig(n_estimators=10, test_ratio=0.2)
        result = trainer.train(training_samples, training_labels, config)
        
        assert result.success == True
        assert result.test_accuracy > 0.5
        print(f"  Training result: {result.message}")
        print(f"  Test accuracy: {result.test_accuracy:.2f}")
        print("  PASSED")
        tests_passed += 1
        
        # Test 14: ModelTrainer feature importance
        print("\nTest: ModelTrainer feature importance...")
        importance = trainer.get_feature_importance(top_n=3)
        assert len(importance) > 0
        print(f"  Top features: {importance[:3]}")
        print("  PASSED")
        tests_passed += 1
        
        # Test 15: ModelTrainer prediction
        print("\nTest: ModelTrainer prediction...")
        pred, prob = trainer.predict({
            "has_login_form": 1,
            "external_submit": 1,
            "suspicious_tld": 1,
            "typo_domain": 1,
            "short_domain": 0,
            "has_ssl": 0
        })
        
        assert pred == 1
        assert prob > 0.5
        print(f"  Prediction: {pred}, Probability: {prob:.2f}")
        print("  PASSED")
        tests_passed += 1
        
        # Test 16: LearningCollector get_training_data
        print("\nTest: LearningCollector get_training_data...")
        collector2 = LearningCollector(storage_path=os.path.join(temp_dir, "samples2.jsonl"))
        
        for i in range(30):
            label = "phishing" if i < 15 else "safe"
            score = 85 if label == "phishing" else 15
            collector2.collect(
                url=f"https://test{i}.com",
                domain=f"test{i}.com",
                features={"score": score},
                risk_score=score,
                ml_probability=score/100,
                final_decision="DANGER" if label == "phishing" else "SAFE",
                source="test"
            )
        
        training_data = collector2.get_training_data(min_samples=10, balanced=True)
        by_label = {}
        for s in training_data:
            by_label[s.label] = by_label.get(s.label, 0) + 1
        
        print(f"  Training data: {by_label}")
        print("  PASSED")
        tests_passed += 1
        
        # Test 17: DatasetManager balanced split
        print("\nTest: DatasetManager balanced split...")
        dm2 = DatasetManager(dataset_path=os.path.join(temp_dir, "dataset2.jsonl"))
        
        for i in range(20):
            dm2.add_entry(
                url=f"https://phish{i}.xyz",
                domain=f"phish{i}.xyz",
                features={"f1": i, "f2": i*2},
                label="phishing",
                source="test"
            )
        
        for i in range(20):
            dm2.add_entry(
                url=f"https://safe{i}.com",
                domain=f"safe{i}.com",
                features={"f1": -i, "f2": i},
                label="safe",
                source="test"
            )
        
        train, test = dm2.get_balanced_split(test_ratio=0.2, min_samples=5)
        print(f"  Train: {len(train)}, Test: {len(test)}")
        print("  PASSED")
        tests_passed += 1
        
    except Exception as e:
        print(f"  FAILED: {e}")
        import traceback
        traceback.print_exc()
        tests_failed += 1
    
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
    
    print("\n" + "=" * 60)
    print(f"Results: {tests_passed} passed, {tests_failed} failed, 0 skipped")
    print("=" * 60)
    
    return tests_failed == 0


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
