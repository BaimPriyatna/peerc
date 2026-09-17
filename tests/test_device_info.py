"""tests/test_device_info.py — Phase 3.4: detect_device_model().

Best-effort and platform-dependent by nature, so these tests focus on
the contract (always a non-empty str, never raises) and the two special
cases (WSL, Termux) that are cheap to force via monkeypatching, rather
than asserting an exact string for every possible host OS.
"""

import core.device_info as device_info


def test_detect_device_model_returns_non_empty_string():
    result = device_info.detect_device_model()
    assert isinstance(result, str)
    assert result.strip() != ""


def test_wsl_detected_via_proc_version(monkeypatch, tmp_path):
    monkeypatch.setattr(device_info.platform, "system", lambda: "Linux")
    monkeypatch.setattr(device_info, "_is_termux", lambda: False)
    monkeypatch.setattr(device_info, "_is_wsl", lambda: True)

    result = device_info.detect_device_model()
    assert "WSL" in result


def test_termux_detected_via_prefix_env(monkeypatch):
    monkeypatch.setattr(device_info.platform, "system", lambda: "Linux")
    monkeypatch.setattr(device_info, "_is_termux", lambda: True)

    result = device_info.detect_device_model()
    assert "Termux" in result


def test_plain_linux_when_neither_wsl_nor_termux(monkeypatch):
    monkeypatch.setattr(device_info.platform, "system", lambda: "Linux")
    monkeypatch.setattr(device_info, "_is_termux", lambda: False)
    monkeypatch.setattr(device_info, "_is_wsl", lambda: False)

    result = device_info.detect_device_model()
    assert result.startswith("Linux")
    assert "WSL" not in result and "Termux" not in result


def test_macos_uses_mac_ver(monkeypatch):
    monkeypatch.setattr(device_info.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(device_info.platform, "mac_ver", lambda: ("14.5", ("", "", ""), ""))

    result = device_info.detect_device_model()
    assert result == "macOS 14.5"


def test_windows_includes_release(monkeypatch):
    monkeypatch.setattr(device_info.platform, "system", lambda: "Windows")
    monkeypatch.setattr(device_info.platform, "release", lambda: "11")

    result = device_info.detect_device_model()
    assert result == "Windows 11"


def test_unknown_system_falls_back_to_system_name(monkeypatch):
    monkeypatch.setattr(device_info.platform, "system", lambda: "SomeOtherOS")

    result = device_info.detect_device_model()
    assert result == "SomeOtherOS"
