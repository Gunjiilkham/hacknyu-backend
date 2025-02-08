import pytest
from services.package_scanner import PackageScanner
from schemas.security import RiskLevel

@pytest.mark.asyncio
async def test_package_scanner():
    scanner = PackageScanner()
    result = await scanner.scan_package("requests", "pypi")
    assert result.is_suspicious is False
    assert result.risk_level == RiskLevel.SAFE

@pytest.mark.asyncio
async def test_malicious_package():
    scanner = PackageScanner()
    result = await scanner.scan_package("malicious-pkg", "npm")
    assert result.is_suspicious is True
    assert result.risk_level == RiskLevel.HIGH 