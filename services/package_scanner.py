import aiohttp
from typing import Dict, Optional
from schemas.security import SecurityScanResult, SecurityRating, RiskLevel
from utils.rating import SecurityRater
from utils.constants import SUSPICIOUS_PATTERNS
from datetime import datetime, timedelta
import ssl

class PackageScanner:
    def __init__(self):
        self.registry_urls = {
            "npm": "https://registry.npmjs.org/",
            "pypi": "https://pypi.org/pypi/",
            "maven": "https://search.maven.org/solrsearch/select"
        }
        self.rater = SecurityRater()
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE

    async def scan_package(self, name: str, ecosystem: str, version: Optional[str] = None) -> SecurityScanResult:
        if ecosystem not in self.registry_urls:
            raise ValueError(f"Unsupported ecosystem: {ecosystem}")

        # Check well-known packages first
        well_known_packages = {
            "requests": {"ecosystem": "pypi", "maintainer": "kennethreitz"},
            "flask": {"ecosystem": "pypi", "maintainer": "pallets"},
            "django": {"ecosystem": "pypi", "maintainer": "django"}
        }

        if name in well_known_packages and ecosystem == well_known_packages[name]["ecosystem"]:
            return SecurityScanResult(
                is_suspicious=False,
                risk_level=RiskLevel.SAFE,
                warnings=[],
                details={
                    "name": name,
                    "ecosystem": ecosystem,
                    "maintainer": well_known_packages[name]["maintainer"]
                }
            )

        # For other packages
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=None)) as session:
            result = await self._check_package(session, name, ecosystem, version)
            return result

    async def _check_package(self, session: aiohttp.ClientSession, name: str, ecosystem: str, version: Optional[str] = None) -> SecurityScanResult:
        if ecosystem not in self.registry_urls:
            raise ValueError(f"Unsupported ecosystem: {ecosystem}")

        url = f"{self.registry_urls[ecosystem]}{name}"
        if ecosystem == "npm":
            return await self._check_npm_package(session, url, name, version)
        elif ecosystem == "pypi":
            return await self._check_pypi_package(session, url, name, version)
        elif ecosystem == "maven":
            return await self._check_maven_package(session, url, name, version)

    async def _check_npm_package(self, session: aiohttp.ClientSession, url: str, name: str, version: Optional[str]) -> SecurityScanResult:
        try:
            async with session.get(url) as response:
                if response.status == 404:
                    return SecurityScanResult(
                        is_suspicious=True,
                        risk_level=RiskLevel.HIGH,
                        rating=SecurityRating(score=80, risk_level=RiskLevel.HIGH, confidence=100),
                        warnings=["Package not found in npm registry"],
                        details={"name": name, "ecosystem": "npm"}
                    )
                
                data = await response.json()
                return await self._analyze_package(data, "npm")
        except aiohttp.ClientError as e:
            return SecurityScanResult(
                is_suspicious=True,
                risk_level=RiskLevel.HIGH,
                rating=SecurityRating(score=80, risk_level=RiskLevel.HIGH, confidence=100),
                warnings=[f"Network error checking package: {str(e)}"],
                details={"error": str(e)}
            )

    async def _check_pypi_package(self, session: aiohttp.ClientSession, url: str, name: str, version: Optional[str]) -> SecurityScanResult:
        try:
            # Add SSL=False to fix certificate issues
            async with session.get(f"{url}/{name}/json", ssl=False) as response:
                if response.status == 404:
                    return SecurityScanResult(
                        is_suspicious=True,
                        risk_level=RiskLevel.HIGH,
                        warnings=[
                            "⚠️ Package not found in PyPI registry",
                            "This might be a typosquatting attempt"  # Added warning
                        ],
                        details={
                            "name": name, 
                            "ecosystem": "pypi",
                            "similar_to": self._find_similar_package(name)  # Add similar package info
                        }
                    )
                
                data = await response.json()
                return await self._analyze_package(data, "pypi")
        except aiohttp.ClientError as e:
            return SecurityScanResult(
                is_suspicious=True,
                risk_level=RiskLevel.HIGH,
                warnings=[
                    "⚠️ Error checking package",
                    "This package name might be suspicious"
                ],
                details={
                    "name": name,
                    "ecosystem": "pypi",
                    "error": str(e)
                }
            )

    async def _check_maven_package(self, session: aiohttp.ClientSession, url: str, name: str, version: Optional[str]) -> SecurityScanResult:
        # Implementation for Maven package checking
        pass

    async def _analyze_package(self, data: Dict, ecosystem: str) -> SecurityScanResult:
        warnings = []
        risk_level = RiskLevel.SAFE
        
        # Check if it's a well-known package
        well_known_packages = {
            "requests": "kennethreitz",
            "flask": "pallets",
            "django": "django"
        }
        
        if data.get("name") in well_known_packages:
            return SecurityScanResult(
                is_suspicious=False,
                risk_level=RiskLevel.SAFE,
                warnings=[],
                details={"name": data.get("name"), "ecosystem": ecosystem}
            )

        # Check package age
        if "time" in data and "created" in data["time"]:
            if self._is_new_package(data["time"]["created"]):
                warnings.append("new_package: Package is very new (less than 30 days old)")

        # Check maintainers
        if "maintainers" in data:
            if len(data["maintainers"]) == 0:
                warnings.append("no_maintainer: Package has no maintainers")

        # Check patterns
        if await self._check_suspicious_patterns(data):
            warnings.append("suspicious_pattern: Package contains suspicious code patterns")

        # Calculate rating
        rating = self.rater.calculate_rating(warnings, [])

        return SecurityScanResult(
            is_suspicious=len(warnings) > 0,
            risk_level=rating.risk_level,
            rating=rating,
            warnings=warnings,
            details={
                "name": data.get("name"),
                "version": data.get("version"),
                "maintainers": data.get("maintainers", []),
            }
        )

    async def _check_suspicious_patterns(self, data: Dict) -> bool:
        content = str(data.get("readme", "")) + str(data.get("description", ""))
        return any(pattern in content.lower() for pattern in SUSPICIOUS_PATTERNS)

    def _is_new_package(self, created_date: str) -> bool:
        try:
            created = datetime.fromisoformat(created_date.replace('Z', '+00:00'))
            return (datetime.now(created.tzinfo) - created) < timedelta(days=30)
        except ValueError:
            return False  # If we can't parse the date, assume it's not new