import app as m
def test_normal_input_is_low_risk():
 risk,matches=m.inspect_input("hello student")
 assert risk=="Low" and matches==[]
def test_union_select_detected():
 risk,matches=m.inspect_input("' UNION SELECT email FROM users --")
 assert risk in ("Medium","High") and matches
def test_health_route():
 r=m.app.test_client().get("/health")
 assert r.status_code==200 and r.get_json()["status"]=="ok"
