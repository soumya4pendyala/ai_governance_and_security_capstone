import unittest
from unittest.mock import patch

from lloydsagent.agent import KeystoneMortgageAgent
from lloydsagent.governance import (
    Risk,
    build_mortgage_risk_register,
    build_regulatory_obligations_register,
    classify_eu_ai_act,
    risk_rating,
    score_risk_register,
)


class AIActClassificationTests(unittest.TestCase):
    def test_mortgage_creditworthiness_is_screened_as_high_risk(self):
        result = classify_eu_ai_act(
            evaluates_creditworthiness=True,
            concerns_natural_person=True,
            fraud_detection_only=False,
        )

        self.assertEqual(result.decision, "HIGH_RISK")
        self.assertEqual(
            result.category,
            "high-risk: creditworthiness of natural persons",
        )
        self.assertTrue(result.human_oversight_required)
        self.assertIn("not legal advice", result.caveat)

    def test_fraud_detection_exception_requires_other_route_review(self):
        result = classify_eu_ai_act(
            evaluates_creditworthiness=True,
            fraud_detection_only=True,
        )

        self.assertEqual(result.decision, "REVIEW")
        self.assertIn("fraud-detection exception", result.category)
        self.assertFalse(result.human_oversight_required)

    def test_potentially_prohibited_use_is_stopped_for_review(self):
        result = classify_eu_ai_act(
            evaluates_creditworthiness=True,
            prohibited_practice=True,
        )

        self.assertEqual(result.decision, "STOP_AND_ESCALATE")
        self.assertTrue(result.human_oversight_required)


class MortgageRiskRegisterTests(unittest.TestCase):
    def test_agent_exposes_governance_assessment_and_register(self):
        with patch.object(KeystoneMortgageAgent, "_init_llm_agent"):
            agent = KeystoneMortgageAgent()

        self.assertEqual(agent.governance_classification.decision, "HIGH_RISK")
        self.assertEqual(agent.risk_register[0]["risk_id"], "KMR-01")

    def test_register_is_sorted_and_scores_inherent_and_residual_risk(self):
        register = build_mortgage_risk_register()

        self.assertGreaterEqual(len(register), 5)
        self.assertEqual(
            register,
            sorted(
                register,
                key=lambda risk: (
                    -risk["residual_score"],
                    -risk["inherent_score"],
                    risk["risk_id"],
                ),
            ),
        )
        self.assertEqual(register[0]["risk_id"], "KMR-01")
        self.assertEqual(register[0]["inherent_score"], 20)
        self.assertEqual(register[0]["inherent_rating"], "Critical")
        self.assertEqual(register[0]["residual_rating"], "Critical")
        self.assertTrue(register[0]["flagged"])
        self.assertEqual(register[0]["action_status"], "ACTION_REQUIRED")
        self.assertTrue(all(risk["owner"] for risk in register))
        self.assertTrue(all(risk["recommended_actions"] for risk in register))
        self.assertFalse(register[-1]["flagged"])
        self.assertEqual(register[-1]["action_status"], "MONITOR")

    def test_risk_scale_and_bands(self):
        self.assertEqual(
            [risk_rating(score) for score in (1, 5, 10, 17, 25)],
            ["Low", "Medium", "High", "Critical", "Critical"],
        )
        with self.assertRaises(ValueError):
            risk_rating(0)
        with self.assertRaises(ValueError):
            Risk(
                "BAD",
                "Bad input",
                "Invalid likelihood",
                6, 2, (), 1, 1, (), "Owner",
            )

    def test_register_rejects_non_risk_entries(self):
        with self.assertRaises(TypeError):
            score_risk_register([{"risk_id": "untyped"}])

    def test_regulatory_register_covers_requested_obligations_as_open_evidence(self):
        register = build_regulatory_obligations_register()
        by_id = {entry["obligation_id"]: entry for entry in register}

        self.assertEqual(len(by_id), len(register))
        self.assertEqual(
            set(by_id),
            {
                "UKGDPR-ART35",
                "UKGDPR-ART30",
                "UKGDPR-LAWFUL-BASIS",
                "UKGDPR-ART28",
                "EUAI-HIGH-RISK",
                "FCA-CONSUMER-DUTY",
                "FCA-MCOB",
                "FCA-SYSC-SMCR",
            },
        )
        self.assertEqual(by_id["UKGDPR-ART35"]["status"], "GAP")
        self.assertEqual(by_id["UKGDPR-ART30"]["status"], "GAP")
        self.assertEqual(by_id["UKGDPR-ART28"]["status"], "GAP")
        self.assertEqual(by_id["EUAI-HIGH-RISK"]["status"], "PARTIAL")
        self.assertEqual(by_id["FCA-CONSUMER-DUTY"]["status"], "DRAFT_ONLY")
        self.assertEqual(by_id["FCA-MCOB"]["status"], "PARTIAL")
        self.assertEqual(by_id["FCA-SYSC-SMCR"]["status"], "GAP")
        self.assertTrue(all(entry["required_actions"] for entry in register))
        self.assertTrue(all(entry["owner"] for entry in register))
        self.assertTrue(all(entry["caveat"] for entry in register))

    def test_regulatory_register_rejects_invalid_status(self):
        from lloydsagent.governance import RegulatoryObligation

        with self.assertRaisesRegex(ValueError, "status"):
            RegulatoryObligation(
                obligation_id="TEST",
                framework="Test",
                provision="Test",
                purpose="Test",
                evidence_found=(),
                status="COMPLIANT",
                required_actions=(),
                owner="Owner",
                caveat="Caveat",
            )


if __name__ == "__main__":
    unittest.main()
