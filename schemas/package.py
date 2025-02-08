from pydantic import BaseModel
from typing import Optional

class PackageCheck(BaseModel):
    name: str
    ecosystem: str  # "npm" | "pypi" | "maven"
    version: Optional[str] = None 