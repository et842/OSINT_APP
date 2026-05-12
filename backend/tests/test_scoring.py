"""Unit tests for the threat-scoring algorithm and indicator-type detection."""
import json
import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from processor import calculate_score, SOURCE_TRUST
from app import detect_indicator_type


def _entry(**overrides):
    base = {
        "indicator_value": "1.2.3.4",
        "source": "",
        "description": "",
        "tags": json.dumps([]),
        "first_seen": None,
    }
    base.update(overrides)
    return base


# Source trust
def test_source_trust_abuseipdb():
    score = calculate_score(_entry(source="abuseipdb"))
    assert score == SOURCE_TRUST["abuseipdb"]


def test_source_trust_urlhaus():
    score = calculate_score(_entry(source="urlhaus"))
    assert score == SOURCE_TRUST["urlhaus"]


def test_source_trust_otx():
    score = calculate_score(_entry(source="otx"))
    assert score == SOURCE_TRUST["otx"]


def test_unknown_source_gets_default_trust():
    """A row with no recognised source still scores something, so it sorts."""
    score = calculate_score(_entry(source="random-feed"))
    assert 0 < score < SOURCE_TRUST["otx"]


# Severity vocabulary
def test_severe_tag_adds_25():
    score = calculate_score(_entry(tags=json.dumps(["malware"])))
    # severity 25 + 1 tag * 2 = 27, plus default source trust
    assert score >= 25


def test_severe_keyword_in_description_counts():
    """URLhaus rows put the threat type in description (e.g. 'malware_download'),
    not in tags - the matcher must catch this."""
    score = calculate_score(_entry(source="urlhaus", description="malware_download"))
    baseline = calculate_score(_entry(source="urlhaus"))
    assert score - baseline >= 25


def test_otx_ttp_tag_counts_as_severe():
    """Regression: OTX tags use TTP names ('credential theft', 'persistence',
    'supply-chain attack') - these must register as severe."""
    score = calculate_score(_entry(
        source="otx",
        tags=json.dumps(["credential theft", "persistence", "supply-chain attack"]),
    ))
    baseline = calculate_score(_entry(source="otx"))
    assert score - baseline >= 25


def test_moderate_tag_adds_15():
    score = calculate_score(_entry(tags=json.dumps(["phishing"])))
    # Has no severe match but should hit moderate.
    assert score >= 15
    assert score < 25 + 10  # didn't accidentally tier up to severe


def test_no_severity_keywords_no_severity_bonus():
    score = calculate_score(_entry(source="otx", tags=json.dumps(["pypi", "wav files"])))
    # source trust + tag richness only - no severity, no recency
    expected = SOURCE_TRUST["otx"] + 2 * 2
    assert score == expected


# Virustotal detection-ratio override
def test_virustotal_high_detection_ratio_scores_high():
    score = calculate_score(_entry(
        source="virustotal",
        description="Malicious detections: 60/60",
    ))
    # 40 from full detection ratio override
    assert score >= 40


def test_virustotal_low_detection_ratio_scores_low():
    score = calculate_score(_entry(
        source="virustotal",
        description="Malicious detections: 1/60",
    ))
    # ~0.7 -> 0 from ratio. Bare VT row.
    assert score < 5


def test_virustotal_missing_detection_falls_back_to_base():
    score = calculate_score(_entry(source="virustotal"))
    assert score == SOURCE_TRUST["virustotal"]


# Tag richness
def test_tag_richness_caps_at_10():
    """A row with many irrelevant tags shouldn't blow past the cap."""
    many_tags = ["tag" + str(i) for i in range(20)]
    score = calculate_score(_entry(source="otx", tags=json.dumps(many_tags)))
    # source 15 + richness cap 10 = 25, no severity match
    assert score == SOURCE_TRUST["otx"] + 10


# Recency
def test_recency_bonus_naive_datetime():
    yesterday = (datetime.now() - timedelta(hours=12)).isoformat()
    score = calculate_score(_entry(source="otx", first_seen=yesterday))
    assert score - SOURCE_TRUST["otx"] >= 15


def test_recency_bonus_timezone_aware_datetime():
    """Regression: indicators with tz-aware first_seen (e.g. URLhaus '...Z') were
    silently losing recency bonus due to operator-precedence bug in processor.py."""
    yesterday = (datetime.now(timezone.utc) - timedelta(hours=12)).isoformat()
    score = calculate_score(_entry(source="otx", first_seen=yesterday))
    assert score - SOURCE_TRUST["otx"] >= 15


def test_urlhaus_timestamp_format_parses():
    """Regression: URLhaus stores first_seen as '2026-03-30 20:33:08 UTC',
    which datetime.fromisoformat rejects. Every URLhaus row was silently
    losing its recency bonus before the parser learned this format."""
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    score = calculate_score(_entry(source="urlhaus", first_seen=now_str))
    assert score - SOURCE_TRUST["urlhaus"] >= 15


def test_old_indicator_gets_no_recency_bonus():
    old = (datetime.now() - timedelta(days=120)).isoformat()
    score = calculate_score(_entry(source="otx", first_seen=old))
    assert score == SOURCE_TRUST["otx"]


# Output range
def test_score_is_clamped_to_100():
    """Even with every signal maxed, the score must not exceed 100."""
    today = datetime.now(timezone.utc).isoformat()
    score = calculate_score(_entry(
        source="virustotal",
        description="Malicious detections: 60/60 ransomware c2",
        tags=json.dumps(["malware", "c2", "ransomware", "trojan", "rat"]),
        first_seen=today,
    ))
    assert score <= 100
    # Should be near the top - strong on every signal
    assert score >= 75


def test_score_is_never_negative():
    score = calculate_score(_entry())
    assert score >= 0


# Realistic-row sanity checks
def test_realistic_urlhaus_row_reaches_high_or_critical():
    """A recent URLhaus malware_download with 2 tags should land in High or
    Critical territory - that's the whole point of recalibration."""
    today = datetime.now(timezone.utc).isoformat()
    score = calculate_score(_entry(
        source="urlhaus",
        description="malware_download",
        tags=json.dumps(["ACRStealer", "ClearFake"]),
        first_seen=today,
    ))
    assert score >= 50  # at least "High"


def test_bare_abuseipdb_row_lands_in_medium_to_high():
    """An AbuseIPDB row with no tags but recent first_seen - should clear the
    Medium threshold (25) so it appears in alerts and isn't lost as noise."""
    today = datetime.now(timezone.utc).isoformat()
    score = calculate_score(_entry(source="abuseipdb", first_seen=today))
    assert score >= 25


# Indicator-type detection (unchanged)
def test_detect_indicator_type():
    assert detect_indicator_type("8.8.8.8") == "ip"
    assert detect_indicator_type("https://example.com/path") == "url"
    assert detect_indicator_type("example.com") == "domain"
    assert detect_indicator_type("d41d8cd98f00b204e9800998ecf8427e") == "hash"  # md5
    assert detect_indicator_type("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == "hash"  # sha256
    assert detect_indicator_type("not-an-indicator") == "unknown"
