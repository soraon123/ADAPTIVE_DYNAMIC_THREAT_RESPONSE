import unittest
import os
import json
from datetime import datetime, timedelta
import detection

class TestDetection(unittest.TestCase):
    def setUp(self):
        # Clean up files before each test
        if os.path.exists(detection.COOLDOWN_FILE):
            os.remove(detection.COOLDOWN_FILE)
        detection._cooldown_cache = None

    def tearDown(self):
        # Clean up files after each test
        if os.path.exists(detection.COOLDOWN_FILE):
            os.remove(detection.COOLDOWN_FILE)
        detection._cooldown_cache = None

    def test_risk_classification(self):
        self.assertEqual(detection.classify_risk(10), "LOW")
        self.assertEqual(detection.classify_risk(50), "MEDIUM")
        self.assertEqual(detection.classify_risk(85), "HIGH")

    def test_alert_cooldown_logic(self):
        process_name = "test_runaway.exe"
        
        # 1. Normal evaluation should trigger an alert
        result = detection.evaluate_process(process_name, 85.0, 5.0)
        self.assertEqual(result["risk"], "HIGH")
        self.assertEqual(result["action"], "alert")
        self.assertEqual(result["reason"], "high-risk")

        # 2. Record action cooldown
        detection.record_action_cooldown(process_name)

        # 3. Process is in cooldown, alert is suppressed
        result_cooldown = detection.evaluate_process(process_name, 85.0, 5.0)
        self.assertEqual(result_cooldown["risk"], "HIGH")
        self.assertEqual(result_cooldown["action"], "ignore")
        self.assertEqual(result_cooldown["reason"], "action-cooldown")

        # 4. Simulate expiration
        cooldowns = detection.load_cooldowns()
        three_hours_ago = (datetime.now() - timedelta(hours=3)).isoformat()
        cooldowns[process_name.lower()] = three_hours_ago
        detection.save_cooldowns(cooldowns)
        
        with detection._cooldown_lock:
            detection._cooldown_cache = cooldowns

        # 5. Process alert is active again
        result_expired = detection.evaluate_process(process_name, 85.0, 5.0)
        self.assertEqual(result_expired["risk"], "HIGH")
        self.assertEqual(result_expired["action"], "alert")
        self.assertEqual(result_expired["reason"], "high-risk")
        
        # Expired cooldown has been purged
        self.assertNotIn(process_name.lower(), detection.load_cooldowns())

if __name__ == "__main__":
    unittest.main()
