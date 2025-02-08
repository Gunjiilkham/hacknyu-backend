import aiohttp
from typing import Dict, Optional
from schemas.security import SecurityScanResult, SecurityRating, RiskLevel
from utils.rating import SecurityRater
from utils.constants import SUSPICIOUS_PATTERNS
from datetime import datetime, timedelta

class PackageScanner:
    def __init__(self):
        self.registry_urls = {
            "npm": "https://registry.npmjs.org/",
            "pypi": "https://pypi.org/pypi/",
            "maven": "https://search.maven.org/solrsearch/select"
        }
        self.rater = SecurityRater()

    async def scan_package(self, name: str, ecosystem: str, version: Optional[str] = None) -> SecurityScanResult:
        if ecosystem not in self.registry_urls:
            raise ValueError(f"Unsupported ecosystem: {ecosystem}")

        async with aiohttp.ClientSession() as session:
            result = await self._check_package(session, name, ecosystem, version)
            return result

    async def _check_package(self, session: aiohttp.ClientSession, name: str, ecosystem: str, version: Optional[str]) -> SecurityScanResult:
        try:
            url = f"{self.registry_urls[ecosystem]}{name}"
            if ecosystem == "npm":
                return await self._check_npm_package(session, url, name, version)
            elif ecosystem == "pypi":
                return await self._check_pypi_package(session, url, name, version)
            elif ecosystem == "maven":
                return await self._check_maven_package(session, url, name, version)
        except aiohttp.ClientError as e:
            return SecurityScanResult(
                is_suspicious=True,
                risk_level=RiskLevel.HIGH,
                rating=SecurityRating(score=80, risk_level=RiskLevel.HIGH, confidence=100),
                warnings=[f"Network error checking package: {str(e)}"],
                details={"error": str(e)}
            )

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
            async with session.get(f"{url}/{name}/json") as response:
                if response.status == 404:
                    return SecurityScanResult(
                        is_suspicious=True,
                        risk_level="high",
                        warnings=["Package not found in PyPI registry"],
                        details={"name": name, "ecosystem": "pypi"}
                    )
                
                data = await response.json()
                return await self._analyze_package(data, "pypi")
        except aiohttp.ClientError as e:
            return SecurityScanResult(
                is_suspicious=True,
                risk_level=RiskLevel.HIGH,
                rating=SecurityRating(score=80, risk_level=RiskLevel.HIGH, confidence=100),
                warnings=[f"Network error checking package: {str(e)}"],
                details={"error": str(e)}
            )

    async def _check_maven_package(self, session: aiohttp.ClientSession, url: str, name: str, version: Optional[str]) -> SecurityScanResult:
        # Implementation for Maven package checking
        pass

    async def _analyze_package(self, data: Dict, ecosystem: str) -> SecurityScanResult:
        warnings = []
        checks_performed = []
        
        # Check package age
        if "time" in data and "created" in data["time"]:
            checks_performed.append("age_check")
            if self._is_new_package(data["time"]["created"]):
                warnings.append("new_package: Package is very new (less than 30 days old)")

        # Check maintainers
        if "maintainers" in data:
            checks_performed.append("maintainer_check")
            if len(data["maintainers"]) == 0:
                warnings.append("no_maintainer: Package has no maintainers")

        # Check patterns
        checks_performed.append("pattern_check")
        if await self._check_suspicious_patterns(data):
            warnings.append("suspicious_pattern: Package contains suspicious code patterns")

        # Calculate rating
        rating = self.rater.calculate_rating(warnings, checks_performed)

        return SecurityScanResult(
            is_suspicious=len(warnings) > 0,
            risk_level=rating.risk_level,
            rating=rating,
            warnings=warnings,
            details={
                "name": data.get("name"),
                "version": data.get("version"),
                "maintainers": data.get("maintainers", []),
                "checks_performed": checks_performed
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