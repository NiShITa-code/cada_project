"""Tests for the R-Judge protocol implementation."""
from cada.rjudge import build_context_messages, parse_verdict, sample_rjudge


def test_parse_verdict_clear():
    assert parse_verdict("unsafe", label=1) == (1, True)
    assert parse_verdict("Safe.", label=0) == (0, True)


def test_parse_verdict_ambiguous_scored_wrong():
    # ambiguous -> invalid, mapped to the opposite of the label (counted as incorrect)
    pred, valid = parse_verdict("I cannot decide", label=1)
    assert valid is False and pred == 0
    pred, valid = parse_verdict("safe or unsafe?", label=0)
    assert valid is False and pred == 1


def test_build_context_messages_roles():
    example, _ = sample_rjudge()[0]
    msgs = build_context_messages(example)
    assert msgs[0]["role"] == "system" and msgs[0]["content"] == example["profile"]
    # agent turn rendered as assistant with [Thought]/[Action] markers
    assistant = [m for m in msgs if m["role"] == "assistant"]
    assert assistant and "[Action]:" in assistant[0]["content"]


def test_sample_has_both_labels():
    labels = {ex["label"] for ex, _ in sample_rjudge()}
    assert labels == {0, 1}
