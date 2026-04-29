"""
HexHunter -- Smart Decision Engine.

Analyzes intermediate results to prioritize and customize subsequent phases.
"""

import re
from dataclasses import dataclass, field

from utils.logger import HexHunterLogger

logger = HexHunterLogger.get_logger("decision")


@dataclass
class TargetProfile:
    """Intelligence profile built from recon data."""
    has_login: bool = False
    has_api: bool = False
    has_file_upload: bool = False
    has_admin_panel: bool = False
    param_count: int = 0
    technologies: list[str] = field(default_factory=list)
    cms: str | None = None
    server: str | None = None
    frameworks: list[str] = field(default_factory=list)
    priority_score: int = 0
    recommendations: list[str] = field(default_factory=list)


class DecisionEngine:
    """
    Analyzes scan results to make smart decisions about next phases.

    Decisions:
        - Login page → prioritize auth testing
        - API endpoints → enable API fuzzing
        - Parameters found → increase fuzzing depth
        - Technology detected → select appropriate checks
    """

    # Patterns indicating login/auth pages
    LOGIN_PATTERNS = [
        r'/login', r'/signin', r'/auth', r'/sso', r'/oauth',
        r'/account', r'/wp-login', r'/admin/login', r'/user/login',
        r'type=["\']password["\']', r'name=["\']password["\']',
    ]

    # Patterns indicating API endpoints
    API_PATTERNS = [
        r'/api/', r'/api/v\d', r'/graphql', r'/rest/',
        r'/swagger', r'/openapi', r'/docs/api',
        r'application/json', r'Content-Type.*json',
    ]

    # Patterns indicating admin panels
    ADMIN_PATTERNS = [
        r'/admin', r'/dashboard', r'/panel', r'/manage',
        r'/wp-admin', r'/administrator', r'/backend',
    ]

    # Patterns indicating file upload
    UPLOAD_PATTERNS = [
        r'type=["\']file["\']', r'/upload', r'multipart/form-data',
        r'enctype=["\']multipart', r'dropzone',
    ]

    def analyze(self, endpoints: list[dict], technologies: list[str],
                scan_results: list[dict]) -> TargetProfile:
        """
        Build a target profile from collected data.

        Args:
            endpoints: Discovered endpoints with URLs and response data
            technologies: Detected technologies
            scan_results: Port/service scan results

        Returns:
            TargetProfile with recommendations
        """
        profile = TargetProfile()
        profile.technologies = technologies

        all_urls = [ep.get("url", "") for ep in endpoints]
        all_bodies = [ep.get("body", "") for ep in endpoints]
        combined_text = " ".join(all_urls + all_bodies)

        # Detect login pages
        for pattern in self.LOGIN_PATTERNS:
            if re.search(pattern, combined_text, re.IGNORECASE):
                profile.has_login = True
                break

        # Detect API endpoints
        for pattern in self.API_PATTERNS:
            if re.search(pattern, combined_text, re.IGNORECASE):
                profile.has_api = True
                break

        # Detect admin panels
        for pattern in self.ADMIN_PATTERNS:
            if re.search(pattern, combined_text, re.IGNORECASE):
                profile.has_admin_panel = True
                break

        # Detect file upload
        for pattern in self.UPLOAD_PATTERNS:
            if re.search(pattern, combined_text, re.IGNORECASE):
                profile.has_file_upload = True
                break

        # Count parameters
        profile.param_count = sum(
            len(ep.get("parameters", "").split(",")) if ep.get("parameters") else 0
            for ep in endpoints
        )

        # Detect CMS
        profile.cms = self._detect_cms(combined_text, technologies)
        profile.server = self._detect_server(technologies)

        # Calculate priority and generate recommendations
        self._calculate_priority(profile)
        self._generate_recommendations(profile)

        logger.info(f"Target profile: priority={profile.priority_score}, "
                     f"login={profile.has_login}, api={profile.has_api}, "
                     f"params={profile.param_count}")

        return profile

    def _detect_cms(self, text: str, techs: list[str]) -> str | None:
        """Detect CMS from response data and technologies."""
        cms_patterns = {
            "wordpress": [r'wp-content', r'wp-includes', r'WordPress'],
            "joomla": [r'Joomla', r'/components/com_'],
            "drupal": [r'Drupal', r'sites/default/files'],
            "magento": [r'Magento', r'mage/cookies'],
        }
        tech_lower = " ".join(techs).lower()
        for cms, patterns in cms_patterns.items():
            for p in patterns:
                if re.search(p, text, re.IGNORECASE) or cms in tech_lower:
                    return cms
        return None

    def _detect_server(self, techs: list[str]) -> str | None:
        """Detect server software from technologies."""
        for tech in techs:
            t = tech.lower()
            if any(s in t for s in ["nginx", "apache", "iis", "caddy", "lighttpd"]):
                return tech
        return None

    def _calculate_priority(self, profile: TargetProfile):
        """Calculate priority score (0-100) based on attack surface."""
        score = 0
        if profile.has_login:
            score += 25
        if profile.has_api:
            score += 20
        if profile.has_admin_panel:
            score += 20
        if profile.has_file_upload:
            score += 15
        if profile.param_count > 10:
            score += 10
        elif profile.param_count > 5:
            score += 5
        if profile.cms:
            score += 10
        profile.priority_score = min(score, 100)

    def _generate_recommendations(self, profile: TargetProfile):
        """Generate actionable recommendations based on profile."""
        recs = []

        if profile.has_login:
            recs.append("LOGIN_DETECTED: Prioritize authentication testing (brute-force, default creds, auth bypass)")
        if profile.has_api:
            recs.append("API_DETECTED: Enable API-specific fuzzing (BOLA, mass assignment, rate limiting)")
        if profile.has_admin_panel:
            recs.append("ADMIN_PANEL: Test for default credentials and access control bypass")
        if profile.has_file_upload:
            recs.append("FILE_UPLOAD: Test for unrestricted file upload, path traversal")
        if profile.param_count > 10:
            recs.append(f"HIGH_PARAMS ({profile.param_count}): Increase fuzzing depth for parameter injection")
        if profile.cms:
            recs.append(f"CMS_DETECTED ({profile.cms}): Run CMS-specific vulnerability checks")

        profile.recommendations = recs

    def get_fuzzing_config(self, profile: TargetProfile) -> dict:
        """Return adjusted fuzzing configuration based on profile."""
        config = {
            "max_depth": 2,
            "param_fuzzing": True,
            "api_fuzzing": profile.has_api,
            "auth_testing": profile.has_login,
            "upload_testing": profile.has_file_upload,
        }

        # Increase depth for parameter-rich targets
        if profile.param_count > 20:
            config["max_depth"] = 4
        elif profile.param_count > 10:
            config["max_depth"] = 3

        return config

    def get_vuln_checks(self, profile: TargetProfile) -> list[str]:
        """Return prioritized list of vulnerability checks."""
        checks = ["xss", "sqli", "open_redirect", "misconfig"]

        if profile.has_api:
            checks.insert(0, "idor")
        if profile.has_login:
            checks.insert(0, "auth_bypass")
        if profile.has_admin_panel:
            checks.insert(0, "access_control")

        return checks
