import aiohttp
from typing import Dict, Optional
from schemas.security import SecurityScanResult
from utils.rating import SecurityRater

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
        url = f"{self.registry_urls[ecosystem]}{name}"
        if ecosystem == "npm":
            return await self._check_npm_package(session, url, name, version)
        elif ecosystem == "pypi":
            return await self._check_pypi_package(session, url, name, version)
        elif ecosystem == "maven":
            return await self._check_maven_package(session, url, name, version)

    async def _check_npm_package(self, session: aiohttp.ClientSession, url: str, name: str, version: Optional[str]) -> SecurityScanResult:
        async with session.get(url) as response:
            if response.status == 404:
                return SecurityScanResult(
                    is_suspicious=True,
                    risk_level="high",
                    warnings=["Package not found in npm registry"],
                    details={"name": name, "ecosystem": "npm"}
                )
            
            data = await response.json()
            return await self._analyze_package(data, "npm")

    async def _check_pypi_package(self, session: aiohttp.ClientSession, url: str, name: str, version: Optional[str]) -> SecurityScanResult:
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
        suspicious_patterns = [
            "eval(",
            "child_process",
            "exec(",
            "http://",
            "curl",
            "wget",
            "bash -c"
        ]
        
        # Check readme and description for suspicious patterns
        content = str(data.get("readme", "")) + str(data.get("description", ""))
        return any(pattern in content.lower() for pattern in suspicious_patterns)

    def _is_new_package(self, created_date: str) -> bool:
        # Implement the logic to determine if a package is new based on its creation date
        # This is a placeholder and should be replaced with the actual implementation
        return False

    async def _check_npm_package(self, session: aiohttp.ClientSession, url: str, name: str, version: Optional[str]) -> SecurityScanResult:
        async with session.get(url) as response:
            if response.status == 404:
                return SecurityScanResult(
                    is_suspicious=True,
                    risk_level="high",
                    warnings=["Package not found in npm registry"],
                    details={"name": name, "ecosystem": "npm"}
                )
            
            data = await response.json()
            return await self._analyze_package(data, "npm")

    async def _check_pypi_package(self, session: aiohttp.ClientSession, url: str, name: str, version: Optional[str]) -> SecurityScanResult:
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

    async def _check_maven_package(self, session: aiohttp.ClientSession, url: str, name: str, version: Optional[str]) -> SecurityScanResult:
        # Implementation for Maven package checking
        pass 