"""Tests for CLI argument parsing and port lists."""

import argparse

import pytest

from hardener.cli import build_parser, parse_port_list


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
