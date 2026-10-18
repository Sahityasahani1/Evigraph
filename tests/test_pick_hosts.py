from src.agent.agent import pick_hosts


def inc(sources, targets):
    return {"top_alert_sources": [{"host_ip": h} for h in sources],
            "top_alert_targets": [{"host_ip": h} for h in targets]}


def test_ddos_victim_is_included_even_with_many_attackers():
    hosts = pick_hosts(inc([f"198.51.100.{i}" for i in range(11, 17)], ["10.0.0.9"]))
    assert "10.0.0.9" in hosts


def test_pivot_host_comes_first():
    hosts = pick_hosts(inc(["10.0.0.6", "203.0.113.20"], ["10.0.0.6", "10.0.0.150"]))
    assert hosts[0] == "10.0.0.6"


def test_limit_and_no_duplicates():
    hosts = pick_hosts(inc(list("abcdef"), list("ghijkl")), limit=4)
    assert len(hosts) == 4 and len(set(hosts)) == 4



def test_compromise_candidates_come_first():
    i = inc(["a", "b"], ["c", "d"])
    i["cross_stage_hosts"] = [{"host_ip": "x", "pattern": "target_then_source"},
                              {"host_ip": "y", "pattern": "source_then_target"}]
    assert pick_hosts(i)[:2] == ["x", "y"]