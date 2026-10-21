import pytest

from chain import cvss


def test_critical_full_impact():
    score, sev = cvss.base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert score == 9.8
    assert sev == "Critical"


def test_medium_low_confidentiality_only():
    score, sev = cvss.base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N")
    assert score == 5.3
    assert sev == "Medium"


def test_none_when_no_impact():
    score, sev = cvss.base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")
    assert score == 0.0
    assert sev == "None"


def test_scope_changed_scales_up():
    u = cvss.base_score("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H")[0]
    c = cvss.base_score("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H")[0]
    assert c > u


def test_invalid_vectors():
    with pytest.raises(cvss.InvalidVector):
        cvss.base_score("CVSS:3.1/AV:N/AC:L")  # missing metrics
    with pytest.raises(cvss.InvalidVector):
        cvss.base_score("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")  # bad value
