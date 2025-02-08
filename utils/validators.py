from typing import Optional
import re

def validate_package_name(name: str) -> bool:
    """Validate package name format"""
    if not name or len(name) > 214:  # npm max length
        return False
    return bool(re.match(r'^[a-zA-Z0-9@/_-]+$', name))

def validate_version(version: Optional[str]) -> bool:
    """Validate semantic version format"""
    if not version:
        return True
    return bool(re.match(r'^\d+\.\d+\.\d+', version))

def validate_url(url: str) -> bool:
    """Validate URL format"""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False 