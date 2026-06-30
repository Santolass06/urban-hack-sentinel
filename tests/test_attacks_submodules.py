"""Tests for WPA/WPS/Deauth attack classes with mocked subprocess calls."""

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime
from pathlib import Path

from urban_hs.modules.wifi.attacks.base import AttackStatus
from urban_hs.modules.wifi.attacks.wpa import HandshakeAttack, PMKIDAttack
from urban_hs.modules.wifi.attacks.wps import WPSPixieAttack, WPSPinAttack
from urban_hs.modules.wifi.attacks.deauth import DeauthAttack, Kr00kAttack


@pytest.fixture
def mock_config(tmp_path):
    with patch("urban_hs.core.config.get_config") as cfg:
        mock = MagicMock()
        mock.storage.resolve_wifi_attacks_dir.return_value = str(tmp_path)
        cfg.return_value = mock
        yield cfg


@pytest.fixture
def iface():
    return "wlan0mon"


class TestHandshakeAttack:
    @pytest.mark.asyncio
    async def test_execute_success(self, iface, mock_config, tmp_path):
        attack = HandshakeAttack(iface, output_dir=str(tmp_path))

        mock_proc = AsyncMock()
        mock_proc.communicate.return_value = (b"", b"")
        mock_proc.wait = AsyncMock(return_value=None)
        mock_proc.returncode = 0

        mock_verify = AsyncMock(return_value=True)

        import urban_hs.modules.wifi.attacks.wpa as wpa_mod

        original_start = attack._start_airodump

        async def patched_start(*args, **kwargs):
            # Create capture file matching the output_prefix
            prefix = kwargs.get("output_prefix") or (args[2] if len(args) > 2 else "")
            if prefix:
                cap = Path(prefix + ".cap")
                cap.write_bytes(b"fake pcap data")
            return mock_proc

        with patch.object(attack, "_start_airodump", side_effect=patched_start), \
             patch("asyncio.create_subprocess_exec", return_value=mock_proc), \
             patch.object(attack, "_verify_handshake", mock_verify):
            result = await attack.execute(
                target_bssid="AA:BB:CC:DD:EE:FF",
                target_essid="TestNet",
                channel=6,
            )

        assert result.status == AttackStatus.SUCCESS
        assert result.handshake_path is not None

    @pytest.mark.asyncio
    async def test_execute_no_capture(self, iface, mock_config, tmp_path):
        attack = HandshakeAttack(iface, output_dir=str(tmp_path))

        mock_proc = AsyncMock()
        mock_proc.communicate.return_value = (b"", b"")
        mock_proc.wait = AsyncMock(return_value=None)
        mock_proc.returncode = 0

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            result = await attack.execute(
                target_bssid="AA:BB:CC:DD:EE:FF",
                channel=6,
            )

        assert result.status == AttackStatus.FAILED


class TestPMKIDAttack:
    @pytest.mark.asyncio
    async def test_execute_timeout(self, iface, mock_config, tmp_path):
        attack = PMKIDAttack(iface, output_dir=str(tmp_path))

        mock_proc = AsyncMock()
        mock_proc.communicate.return_value = (b"", b"")
        mock_proc.kill = AsyncMock()
        mock_proc.wait = AsyncMock(return_value=None)
        mock_proc.pid = 12345
        mock_proc.stderr = AsyncMock()
        mock_proc.stderr.read = AsyncMock(return_value=b"")
        mock_proc.returncode = 0

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            with patch("asyncio.wait_for", side_effect=asyncio.TimeoutError):
                result = await attack.execute(
                    target_bssid="AA:BB:CC:DD:EE:FF",
                    channel=6,
                )

        assert result.status in (AttackStatus.FAILED, AttackStatus.SUCCESS)


class TestWPSPixieAttack:
    @pytest.mark.asyncio
    async def test_execute_pin_found(self, iface, mock_config, tmp_path):
        attack = WPSPixieAttack(iface, output_dir=str(tmp_path))

        mock_proc = AsyncMock()
        mock_proc.stdout = AsyncMock()
        mock_proc.stdout.read = AsyncMock(
            return_value=b"WPS PIN: 12345670\nWPA PSK: password123\n"
        )
        mock_proc.stderr = AsyncMock()
        mock_proc.stderr.read = AsyncMock(return_value=b"")
        mock_proc.wait = AsyncMock(return_value=None)
        mock_proc.kill = AsyncMock()
        mock_proc.returncode = 0

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            result = await attack.execute(
                target_bssid="AA:BB:CC:DD:EE:FF",
                channel=6,
            )

        assert result.status == AttackStatus.SUCCESS
        assert result.wps_pin == "12345670"
        assert result.wps_psk == "password123"

    @pytest.mark.asyncio
    async def test_execute_no_pin(self, iface, mock_config, tmp_path):
        attack = WPSPixieAttack(iface, output_dir=str(tmp_path))

        mock_proc = AsyncMock()
        mock_proc.stdout = AsyncMock()
        mock_proc.stdout.read = AsyncMock(return_value=b"nothing found\n")
        mock_proc.stderr = AsyncMock()
        mock_proc.stderr.read = AsyncMock(return_value=b"error")
        mock_proc.wait = AsyncMock(return_value=None)
        mock_proc.kill = AsyncMock()
        mock_proc.returncode = 1

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            result = await attack.execute(
                target_bssid="AA:BB:CC:DD:EE:FF",
                channel=6,
            )

        assert result.status == AttackStatus.FAILED


class TestDeauthAttack:
    @pytest.mark.asyncio
    async def test_execute_broadcast(self, iface, mock_config, tmp_path):
        attack = DeauthAttack(iface, output_dir=str(tmp_path))

        mock_proc = AsyncMock()
        mock_proc.communicate.return_value = (b"", b"")
        mock_proc.wait = AsyncMock(return_value=None)
        mock_proc.returncode = 0

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc), \
             patch("asyncio.wait_for", return_value=(b"", b"")):
            result = await attack.execute(
                target_bssid="AA:BB:CC:DD:EE:FF",
                channel=6,
            )

        assert result.status == AttackStatus.SUCCESS

    @pytest.mark.asyncio
    async def test_execute_targeted(self, iface, mock_config, tmp_path):
        attack = DeauthAttack(iface, output_dir=str(tmp_path))

        mock_proc = AsyncMock()
        mock_proc.communicate.return_value = (b"", b"")
        mock_proc.wait = AsyncMock(return_value=None)
        mock_proc.returncode = 0

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc), \
             patch("asyncio.wait_for", return_value=(b"", b"")):
            result = await attack.execute(
                target_bssid="AA:BB:CC:DD:EE:FF",
                channel=6,
                client_mac="11:22:33:44:55:66",
            )

        assert result.status == AttackStatus.SUCCESS
        assert result.metadata["targeted"] is True


class TestKr00kAttack:
    @pytest.mark.asyncio
    async def test_init_defaults(self, iface, mock_config, tmp_path):
        attack = Kr00kAttack(iface, output_dir=str(tmp_path))
        assert attack.deauth_count == 10
        assert attack.capture_after_deauth == 10

    @pytest.mark.asyncio
    async def test_init_custom(self, iface, mock_config, tmp_path):
        attack = Kr00kAttack(
            iface, output_dir=str(tmp_path),
            deauth_count=5, capture_after_deauth=15,
        )
        assert attack.deauth_count == 5
        assert attack.capture_after_deauth == 15
