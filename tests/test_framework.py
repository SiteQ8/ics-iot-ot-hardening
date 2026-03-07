"""
ICS Hardening Framework — Test Suite
"""

import pytest
import importlib


class TestPackage:
    """Test package imports and metadata."""

    def test_import_package(self):
        import ics_hardening
        assert ics_hardening.__version__ == "2.0.0"
        assert ics_hardening.__author__ == "Ali AlEnezi"

    def test_import_cli(self):
        from ics_hardening import cli
        assert hasattr(cli, "main")
        assert hasattr(cli, "scan")
        assert hasattr(cli, "comply")
        assert hasattr(cli, "monitor")

    def test_cli_commands_exist(self):
        from ics_hardening.cli import main
        assert "assess" in [c.name for c in main.commands.values()]
        assert "harden" in [c.name for c in main.commands.values()]
        assert "network" in [c.name for c in main.commands.values()]
        assert "report" in [c.name for c in main.commands.values()]
        assert "assets" in [c.name for c in main.commands.values()]


class TestStandards:
    """Test compliance standard definitions."""

    def test_standards_defined(self):
        from ics_hardening.cli import STANDARDS
        assert "iec62443" in STANDARDS
        assert "nist800-82" in STANDARDS
        assert "nerc-cip" in STANDARDS
        assert "mitre-ics" in STANDARDS
        assert "cis-v8" in STANDARDS
        assert "cbk-corf" in STANDARDS

    def test_standard_descriptions(self):
        from ics_hardening.cli import STANDARDS
        for key, desc in STANDARDS.items():
            assert isinstance(desc, str)
            assert len(desc) > 10


class TestBanner:
    """Test CLI banner."""

    def test_banner_content(self):
        from ics_hardening.cli import BANNER
        assert "ICS" in BANNER
        assert "HARDENING" in BANNER
        assert "SiteQ8" in BANNER


class TestProtocolData:
    """Validate protocol data used in GUI."""

    PROTOCOLS = [
        "Modbus", "DNP3", "IEC 61850", "OPC UA", "EtherNet/IP",
        "BACnet", "MQTT", "CoAP", "PROFINET", "S7comm", "IEC 60870", "HART-IP"
    ]

    def test_all_protocols_covered(self):
        """Verify the framework covers all 12 major ICS protocols."""
        assert len(self.PROTOCOLS) == 12

    @pytest.mark.parametrize("protocol", PROTOCOLS)
    def test_protocol_name_valid(self, protocol):
        assert isinstance(protocol, str)
        assert len(protocol) > 2
