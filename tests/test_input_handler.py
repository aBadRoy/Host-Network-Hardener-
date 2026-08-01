"""Tests for target input parsing."""

import pytest

from hardener.input_handler import TargetParseError, expand_targets, parse_targets


def test_parse_single_ip():
    targets = parse_targets(["127.0.0.1"])
    assert len(targets) == 1
    t = targets[0]
    assert t.ip == "127.0.0.1"
    assert t.kind == "single_ip"
    assert t.ip_list == ["127.0.0.1"]


def test_parse_multiple_comma_separated():
    targets = parse_targets(["10.0.0.1,10.0.0.2"])
    assert len(targets) == 2
    assert {t.ip for t in targets} == {"10.0.0.1", "10.0.0.2"}


def test_parse_dedupes():
    targets = parse_targets(["127.0.0.1", "127.0.0.1"])
    assert len(targets) == 1


def test_parse_hostname_no_resolution_required():
    targets = parse_targets(["no-such-host.invalid"])
    assert len(targets) == 1
    assert targets[0].kind == "hostname"
    assert targets[0].hostname == "no-such-host.invalid"


def test_parse_cidr_expansion():
    targets = parse_targets(["10.0.0.0/30"])
    assert len(targets) == 1
    assert targets[0].kind == "cidr"
    assert len(targets[0].ip_list) == 2  # .1 and .2 usable hosts


def test_parse_cidr_32():
    targets = parse_targets(["10.0.0.9/32"])
    assert targets[0].ip_list == ["10.0.0.9"]


def test_parse_invalid_raises():
    with pytest.raises(TargetParseError):
        parse_targets(["not a valid target !!!"])


def test_parse_no_targets_raises():
    with pytest.raises(TargetParseError):
        parse_targets([])


def test_parse_target_file(tmp_path):
    f = tmp_path / "targets.txt"
    f.write_text("# comment line\n127.0.0.1\n10.0.0.1\n", encoding="utf-8")
    targets = parse_targets([], str(f))
    assert len(targets) == 2


def test_expand_targets_flattens_cidr():
    cidr = parse_targets(["192.168.1.0/30"])[0]
    expanded = expand_targets([cidr])
    assert len(expanded) == 2
    assert all(t.kind == "single_ip" for t in expanded)
    assert expanded[0].network == "192.168.1.0/30"
