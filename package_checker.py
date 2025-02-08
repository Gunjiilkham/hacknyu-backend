import requests
from typing import Dict, List, Optional

class PackageChecker:
    def __init__(self):
        self.registry_urls = {
            "npm": "https://registry.npmjs.org/",
            "pypi": "https://pypi.org/pypi/",
            "maven": "https://search.maven.org/solrsearch/select"
        }

    async def check_package(self, name: str, ecosystem: str, version: Optional[str] = None) -> Dict:
        if ecosystem not in self.registry_urls:
            raise ValueError(f"Unsupported ecosystem: {ecosystem}")

        try:
            if ecosystem == "npm":
                return await self._check_npm_package(name, version)
            elif ecosystem == "pypi":
                return await self._check_pypi_package(name, version)
            elif ecosystem == "maven":
                return await self._check_maven_package(name, version)
        except Exception as e:
            raise Exception(f"Error checking package: {str(e)}")

    async def _check_npm_package(self, name: str, version: Optional[str] = None) -> Dict:
        url = f"{self.registry_urls['npm']}{name}"
        response = requests.get(url)
        if response.status_code == 404:
            return {
                "is_suspicious": True,
                "risk_level": "high",
                "warnings": ["Package not found in npm registry"]
            }
        
        data = response.json()
        return self._analyze_npm_package(data)

    def _analyze_npm_package(self, data: Dict) -> Dict:
        warnings = []
        risk_level = "low"

        # Check package age
        if "time" in data and "created" in data["time"]:
            # Add age-based checks here
            pass

        # Check download counts
        if "downloads" in data:
            # Add popularity-based checks here
            pass

        # Check maintainers
        if "maintainers" in data and len(data["maintainers"]) == 0:
            warnings.append("Package has no maintainers")
            risk_level = "high"

        return {
            "is_suspicious": len(warnings) > 0,
            "risk_level": risk_level,
            "warnings": warnings,
            "details": {
                "name": data.get("name"),
                "version": data.get("version"),
                "maintainers": data.get("maintainers", [])
            }
        }

    # TODO: Implement PyPI and Maven package checking methods
    async def _check_pypi_package(self, name: str, version: Optional[str] = None) -> Dict:
        pass

    async def _check_maven_package(self, name: str, version: Optional[str] = None) -> Dict:
        pass 