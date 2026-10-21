from chain.checks import wrapped


def test_sqlmap_positive():
    out = "Parameter: id (GET)\n    Type: boolean-based blind\n    Title: AND boolean-based blind"
    v, _ = wrapped.parse_sqlmap(out)
    assert v == "candidate"


def test_sqlmap_negative():
    out = "all tested parameters do not appear to be injectable"
    v, _ = wrapped.parse_sqlmap(out)
    assert v == "tested_negative"


def test_dalfox_positive():
    out = '{"type":"V","evidence":"<script>alert(1)</script>"}'
    v, _ = wrapped.parse_dalfox(out)
    assert v == "candidate"


def test_dalfox_negative():
    assert wrapped.parse_dalfox("")[0] == "tested_negative"
    assert wrapped.parse_dalfox('{"type":"I","info":"x"}')[0] == "tested_negative"


def test_nuclei_positive():
    out = '{"template-id":"CVE-2021-1234","info":{"severity":"high"}}\n{"template-id":"ssti-detect"}'
    v, reason = wrapped.parse_nuclei(out)
    assert v == "candidate"
    assert "CVE-2021-1234" in reason


def test_nuclei_negative():
    assert wrapped.parse_nuclei("")[0] == "tested_negative"


def test_sstimap_positive_negative():
    assert wrapped.parse_sstimap("[+] SSTImap identified the following injection point:\n  Engine: Jinja2")[0] == "candidate"
    assert wrapped.parse_sstimap("[-] SSTImap could not find any injection point")[0] == "tested_negative"


def test_testssl_positive_negative():
    hi = '[{"id":"BEAST","severity":"HIGH","finding":"VULNERABLE","cve":"CVE-2011-3389"}]'
    v, reason = wrapped.parse_testssl(hi)
    assert v == "candidate" and "CVE-2011-3389" in reason
    lo = '[{"id":"cipher","severity":"LOW","finding":"ok"}]'
    assert wrapped.parse_testssl(lo)[0] == "tested_negative"
    assert wrapped.parse_testssl("not json")[0] == "tested_negative"


def test_adapter_mapping_and_argv():
    a = wrapped.adapter_for("sqli")
    assert a.tool == "sqlmap"
    argv = a.build_argv("https://x/items?id=1", "id")
    assert "-p" in argv and "id" in argv
    assert wrapped.adapter_for("xss").tool == "dalfox"
    assert wrapped.adapter_for("ssti").tool == "sstimap"  # SSTImap now owns SSTI
    assert wrapped.adapter_for("cmdi").tool == "nuclei"
    assert wrapped.adapter_for("tls").tool == "testssl"
    assert wrapped.adapter_for("authz_idor") is None  # no wrapped tool for authz
