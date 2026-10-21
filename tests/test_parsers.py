from chain.recon import parsers

NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="93.184.216.34" addrtype="ipv4"/>
    <hostnames><hostname name="example.com" type="user"/></hostnames>
    <ports>
      <port protocol="tcp" portid="443"><state state="open"/>
        <service name="https" product="nginx" version="1.18.0"/></port>
      <port protocol="tcp" portid="22"><state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.2"/></port>
      <port protocol="tcp" portid="81"><state state="closed"/>
        <service name="http"/></port>
    </ports>
    <os><osmatch name="Linux 5.X"/></os>
  </host>
</nmaprun>"""


def test_parse_nmap_xml():
    hosts = parsers.parse_nmap_xml(NMAP_XML)
    assert len(hosts) == 1
    h = hosts[0]
    assert h["ip"] == "93.184.216.34"
    assert h["hostname"] == "example.com"
    assert h["os_guess"] == "Linux 5.X"
    ports = {s["port"]: s for s in h["services"]}
    assert set(ports) == {443, 22}  # closed port 81 dropped
    assert ports[443]["is_http"] is True
    assert ports[22]["is_http"] is False
    assert ports[443]["product"] == "nginx"


def test_parse_nmap_garbage():
    assert parsers.parse_nmap_xml("not xml") == []


def test_parse_httpx_jsonl():
    text = (
        '{"url":"https://example.com","host":"93.184.216.34","port":"443",'
        '"scheme":"https","status_code":200,"webserver":"nginx","tech":["Nginx"],"title":"Home"}\n'
        "\n"
        "garbage line\n"
    )
    recs = parsers.parse_httpx_jsonl(text)
    assert len(recs) == 1
    assert recs[0]["port"] == 443
    assert recs[0]["scheme"] == "https"
    assert recs[0]["webserver"] == "nginx"


def test_parse_ffuf_results_object():
    text = '{"results":[{"url":"https://example.com/admin","status":200,"length":42},' \
           '{"url":"https://example.com/login","status":200,"length":10}]}'
    recs = parsers.parse_ffuf_json(text)
    paths = sorted(r["path"] for r in recs)
    assert paths == ["/admin", "/login"]


def test_parse_katana_jsonl():
    text = (
        '{"request":{"method":"GET","endpoint":"https://example.com/api/users?id=1&q=x"}}\n'
        '{"request":{"method":"POST","endpoint":"https://example.com/api/login"}}\n'
    )
    recs = parsers.parse_katana_jsonl(text)
    assert recs[0]["method"] == "GET"
    assert recs[0]["path"] == "/api/users"
    assert "id=1" in recs[0]["query"]
    assert recs[1]["method"] == "POST"


def test_parse_subfinder():
    text = "api.example.com\nwww.example.com\napi.example.com\n\n"
    assert parsers.parse_subfinder(text) == ["api.example.com", "www.example.com"]
