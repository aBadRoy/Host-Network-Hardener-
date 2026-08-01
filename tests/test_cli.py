"""Tests for CLI argument parsing and port lists."""

import argparse

import pytest

from hardener.cli import build_parser, parse_port_list, resolve_scan_type


def test_parse_port_list_simple():
    assert parse_port_list("22,80,443") == [22, 80, 443]


def test_parse_port_list_range():
    assert parse_port_list("80-82") == [80, 81, 82]


def test_parse_port_list_mixed():
    assert parse_port_list("22,80-82,443") == [22, 80, 81, 82, 443]


def test_parse_port_list_full_range():
    ports = parse_port_list("0-65535")
    assert len(ports) == 65536
    assert ports[0] == 0
    assert ports[-1] == 65535


def test_parse_port_list_dedupes():
    assert parse_port_list("80,80,80-81") == [80, 81]


def test_parse_port_list_invalid():
    with pytest.raises(argparse.ArgumentTypeError):
        parse_port_list("abc")
    with pytest.raises(argparse.ArgumentTypeError):
        parse_port_list("70000")
    with pytest.raises(argparse.ArgumentTypeError):
        parse_port_list("90-80")


def test_parser_defaults():
    args = build_parser().parse_args(["-t", "127.0.0.1"])
    assert args.targets == ["127.0.0.1"]
    assert args.ports is None
    assert args.all_ports is False
    assert args.authorized is False


def test_parser_all_ports_flag():
    args = build_parser().parse_args(["--all-ports", "-t", "127.0.0.1"])
    assert args.all_ports is True


def test_parser_range_ports():
    args = build_parser().parse_args(["-t", "127.0.0.1", "-p", "1-100,8080"])
    assert args.ports == list(range(1, 101)) + [8080]


def test_parser_verbose_count():
    args = build_parser().parse_args(["-vvv", "-d"])
    assert args.verbose == 3
    assert args.debug == 1


def test_parser_timing_template():
    args = build_parser().parse_args(["-T4", "-t", "127.0.0.1"])
    assert args.timing == 4
    args = build_parser().parse_args(["-T0", "-t", "127.0.0.1"])
    assert args.timing == 0


def test_parser_fast_and_top_ports():
    args = build_parser().parse_args(["-F", "-t", "127.0.0.1"])
    assert args.fast is True
    args = build_parser().parse_args(["--top-ports", "50", "-t", "127.0.0.1"])
    assert args.top_ports == 50


def test_parser_scan_type():
    args = build_parser().parse_args(["--scan-type", "ack", "-t", "127.0.0.1"])
    assert args.scan_type == "ack"


def test_parser_rate_and_retries():
    args = build_parser().parse_args(["--max-rate", "500", "--max-retries", "3",
                                      "--stats-every", "5", "-t", "127.0.0.1"])
    assert args.max_rate == 500.0
    assert args.max_retries == 3
    assert args.stats_every == 5


def test_parser_grepable_and_reason():
    args = build_parser().parse_args(["-oG", "out.gnmap", "--reason", "--open",
                                      "-t", "127.0.0.1"])
    assert args.grepable == "out.gnmap"
    assert args.reason is True
    assert args.open is True


def test_parser_ping_sweep_and_probes():
    args = build_parser().parse_args(["-sn", "-PA", "-PU", "-t", "127.0.0.1"])
    assert args.ping_sweep is True
    assert args.ack_ping is True
    assert args.udp_ping is True


def test_parser_aggressive():
    args = build_parser().parse_args(["-A", "-t", "127.0.0.1"])
    assert args.aggressive is True


def test_parser_exclude_ports():
    args = build_parser().parse_args(["--exclude-ports", "22,80-82",
                                      "-t", "127.0.0.1"])
    assert args.exclude_ports == [22, 80, 81, 82]


def test_parser_nmap_flag_default():
    args = build_parser().parse_args(["-t", "127.0.0.1"])
    assert args.use_nmap is None


def test_parser_nmap_flag_on_and_off():
    args = build_parser().parse_args(["--nmap", "-t", "127.0.0.1"])
    assert args.use_nmap is True
    args = build_parser().parse_args(["--no-nmap", "-t", "127.0.0.1"])
    assert args.use_nmap is False


def test_resolve_scan_type_syn_from_flag_and_aggressive():
    assert resolve_scan_type(False, True, "connect") == "syn"
    assert resolve_scan_type(True, True, "connect") == "syn"


def test_resolve_scan_type_keeps_explicit_choice():
    assert resolve_scan_type(True, True, "ack") == "ack"
    assert resolve_scan_type(True, False, "null") == "null"
    assert resolve_scan_type(False, False, "connect") == "connect"
