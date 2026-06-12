"""Tests for the obfuscation suite."""
import base64

from cada import obfuscation


def test_clean_is_identity():
    assert obfuscation.o0_plain("cat /etc/shadow") == "cat /etc/shadow"


def test_transforms_change_surface_text():
    cmd = "cat /etc/shadow"
    for name, fn in obfuscation.TRANSFORMS.items():
        out = fn(cmd)
        if name == "O0_clean":
            assert out == cmd
        else:
            assert out != cmd, f"{name} did not alter the surface text"


def test_base64_roundtrips_to_original():
    cmd = "cat /etc/shadow"
    wrapped = obfuscation.o1_base64(cmd)
    blob = wrapped.split("echo ")[1].split(" |")[0]
    assert base64.b64decode(blob).decode() == cmd


def test_obfuscations_hide_keywords():
    # base64 / dynamic-import variants must not leak the literal sensitive path
    cmd = "cat /etc/shadow"
    assert "/etc/shadow" not in obfuscation.o1_base64(cmd)
    assert "/etc/shadow" not in obfuscation.o4_dynamic_import(cmd)


def test_held_out_family_is_separate():
    assert "H1_hex" in obfuscation.HELD_OUT
    assert "H1_hex" not in obfuscation.TRANSFORMS
