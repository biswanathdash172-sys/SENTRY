"""
test_media_integrity.py
------------------------
Real unit tests for services/media_integrity_service.py.

IMPORTANT CONTEXT (see deepfake_detector.py's own docstring): the scoring
here is an intentional, documented heuristic for a hackathon demo — NOT a
trained model. These tests verify the heuristic's *contract* (verdicts,
signature lookups, evidence conversion) is correct and stable, not that
it accurately detects real deepfakes. If/when a real classifier backend
is wired in, these tests should still pass unchanged for the
force_verdict path, and the heuristic-only tests should move to
test_deepfake_detector.py alongside the new model tests.
"""
import pytest

from models import MediaVerifyRequest
from services import media_integrity_service as mis


class TestForceVerdictOverrides:
    """force_verdict lets demos/tests get a deterministic result without
    depending on the heuristic's filename-hash math."""

    def test_force_authentic(self):
        req = MediaVerifyRequest(filename="anything.mp4", force_verdict="authentic")
        result = mis.verify_media(req)
        assert result.verdict == "authentic"
        assert result.signature_valid is True
        assert result.signer is not None
        assert result.deepfake_likelihood < 0.1

    def test_force_authentic_uses_claimed_sender_when_given(self):
        req = MediaVerifyRequest(
            filename="anything.mp4", claimed_sender="Jane CFO", force_verdict="authentic"
        )
        result = mis.verify_media(req)
        assert result.signer == "Jane CFO"

    def test_force_deepfake(self):
        req = MediaVerifyRequest(filename="clean_name.mp4", force_verdict="deepfake")
        result = mis.verify_media(req)
        assert result.verdict == "deepfake"
        assert result.signature_valid is False
        assert result.signer is None
        assert result.deepfake_likelihood >= 0.9

    def test_force_unsigned(self):
        req = MediaVerifyRequest(filename="clean_name.mp4", force_verdict="unsigned")
        result = mis.verify_media(req)
        assert result.verdict == "unsigned"
        assert result.signature_valid is False


class TestSignatureRegistryLookup:
    def test_known_signed_filename_is_recognized(self):
        req = MediaVerifyRequest(filename="quarterly_update_signed.mp4")
        result = mis.verify_media(req)
        assert result.signature_valid is True
        assert result.signer == "CFO Office (verified)"

    def test_lookup_is_case_insensitive(self):
        req = MediaVerifyRequest(filename="QUARTERLY_UPDATE_SIGNED.MP4")
        result = mis.verify_media(req)
        assert result.signature_valid is True

    def test_unknown_filename_has_no_signer(self):
        req = MediaVerifyRequest(filename="random_unregistered_file.mp4")
        result = mis.verify_media(req)
        assert result.signature_valid is False
        assert result.signer is None


class TestHeuristicVerdictLogic:
    def test_filename_containing_deepfake_scores_high_and_flags_deepfake(self):
        req = MediaVerifyRequest(filename="urgent_cfo_deepfake_request.mp4")
        result = mis.verify_media(req)
        assert result.deepfake_likelihood >= 0.55
        assert result.verdict in ("deepfake", "suspicious")

    def test_unsigned_file_is_never_verdict_authentic(self):
        # Even a "clean" filename with a low score can't be marked authentic
        # unless it has a valid signature (signature_valid and score < 0.3).
        req = MediaVerifyRequest(filename="totally_unregistered_clean_name.mp4")
        result = mis.verify_media(req)
        assert result.verdict != "authentic"

    def test_signed_and_low_score_is_authentic(self):
        req = MediaVerifyRequest(filename="quarterly_update_signed.mp4")
        result = mis.verify_media(req)
        # This filename is both in SIGNED_REGISTRY and doesn't contain
        # deepfake/fake/cfo/urgent bias keywords, so score should be < 0.3.
        assert result.verdict == "authentic"

    def test_heuristic_score_is_deterministic_for_same_filename(self):
        req1 = MediaVerifyRequest(filename="repeat_this_file.mp4")
        req2 = MediaVerifyRequest(filename="repeat_this_file.mp4")
        r1 = mis.verify_media(req1)
        r2 = mis.verify_media(req2)
        assert r1.deepfake_likelihood == r2.deepfake_likelihood
        assert r1.verdict == r2.verdict

    def test_score_is_always_within_valid_range(self):
        for name in ["a.mp4", "deepfake_test.mp4", "cfo_urgent_wire.mp4", "zzz.mp4"]:
            result = mis.verify_media(MediaVerifyRequest(filename=name))
            assert 0.0 <= result.deepfake_likelihood <= 1.0


class TestResultToEvidence:
    def test_authentic_result_produces_low_confidence_evidence(self):
        req = MediaVerifyRequest(filename="quarterly_update_signed.mp4", force_verdict="authentic")
        result = mis.verify_media(req)
        evidence = mis.result_to_evidence(result)
        assert evidence.source_type == "media"
        assert evidence.confidence == 0.1
        assert "verified" in evidence.description.lower()

    def test_deepfake_result_produces_high_confidence_evidence(self):
        req = MediaVerifyRequest(filename="clean_name.mp4", force_verdict="deepfake")
        result = mis.verify_media(req)
        evidence = mis.result_to_evidence(result)
        assert evidence.source_type == "media"
        assert evidence.confidence == pytest.approx(result.deepfake_likelihood)
        assert "failed integrity check" in evidence.description.lower()

    def test_unsigned_low_score_result_still_has_meaningful_confidence_floor(self):
        req = MediaVerifyRequest(filename="clean_name.mp4", force_verdict="unsigned")
        result = mis.verify_media(req)
        evidence = mis.result_to_evidence(result)
        # confidence = max(deepfake_likelihood, 0.3 if not signature_valid else 0.0)
        assert evidence.confidence >= 0.3