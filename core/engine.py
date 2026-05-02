"""
HexHunterX -- Core Execution Engine.

Orchestrates the full pentesting pipeline:
Recon → Scanning → Fuzzing → Vulnerability Checks → Reporting
"""

import asyncio
import time
from pathlib import Path

import yaml

from core.decision import DecisionEngine, TargetProfile
from core.scheduler import TaskScheduler, PhaseStatus
from database.manager import DatabaseManager
from database.models import Target, Subdomain, Endpoint, ScanResult, Vulnerability
from utils.logger import HexHunterXLogger
from utils.network import AsyncHTTPClient
from utils.validators import InputValidator, TargetType
from modules.vulns.deduplication import FindingDeduplicator
import json

# AI-ENHANCED
from ai.triage import triage_finding

logger = HexHunterXLogger.get_logger("engine")


class HexHunterXEngine:
    """
    Main execution engine that orchestrates the pentesting workflow.

    Flow:
        1. Validate target
        2. Initialize database and HTTP client
        3. Run phases in sequence (with skip/resume support)
        4. Store results after each phase
        5. Generate report
    """

    def __init__(self, config: dict):
        self.config = config
        self.db = DatabaseManager(config.get("database", {}).get("path", "HexHunterX.db"))
        self.scheduler = TaskScheduler(config.get("general", {}).get("threads", 50))
        self.decision = DecisionEngine()
        self.http_client: AsyncHTTPClient | None = None
        self.target_id: int | None = None
        self.target_profile: TargetProfile | None = None
        self._start_time: float = 0
        self.auth_manager = None
        self.oob_client = None

    async def initialize(self):
        """Initialize database, HTTP client, auth, and OOB."""
        await self.db.connect()
        self.http_client = AsyncHTTPClient(
            rate_limit=self.config.get("general", {}).get("rate_limit", 10),
            max_retries=self.config.get("general", {}).get("max_retries", 3),
            timeout=self.config.get("general", {}).get("timeout", 10),
            user_agent=self.config.get("general", {}).get("user_agent", "HexHunterX/1.0"),
            max_connections=self.config.get("general", {}).get("threads", 50),
        )

        # ─── Auth Setup ────────────────────────────────
        auth_config = self.config.get("auth", {})
        if auth_config:
            from utils.auth import AuthManager
            self.auth_manager = AuthManager.from_config(auth_config)
            # Inject auth into HTTP client before session starts
            self.http_client.set_auth(
                headers=self.auth_manager.auth_headers,
                cookies=self.auth_manager.auth_cookies,
            )

        await self.http_client.start()

        # Auto-login if credentials provided
        if self.auth_manager and self.auth_manager.needs_login:
            success = await self.auth_manager.login(self.http_client)
            if success:
                # Re-inject captured cookies into the session
                self.http_client.set_auth(cookies=self.auth_manager.auth_cookies)
            else:
                logger.warning("Auto-login failed -- continuing without auth")

        # ─── OOB Setup ─────────────────────────────────
        oob_config = self.config.get("oob", {})
        if oob_config.get("enabled"):
            from integrations.interactsh import InteractshClient
            self.oob_client = InteractshClient(
                server=oob_config.get("server"),
                token=oob_config.get("token"),
                poll_interval=oob_config.get("poll_interval", 5),
            )
            await self.oob_client.register()

        logger.success("Engine initialized")

    async def shutdown(self):
        """Clean up resources."""
        if self.oob_client and self.oob_client.is_registered:
            await self.oob_client.stop_polling()
            await self.oob_client.deregister()
        if self.http_client:
            await self.http_client.close()
        await self.db.close()
        logger.info("Engine shut down")

    async def run(self, target: str, phases: list[str], resume: bool = False):
        """
        Execute the pentesting pipeline.

        Args:
            target: Raw target input (domain, IP, CIDR, URL)
            phases: List of phases to run (recon, scan, fuzz, vuln, report)
            resume: If True, skip phases that already have data
        """
        self._start_time = time.monotonic()

        try:
            await self.initialize()

            # ─── Validate Target ────────────────────────
            validated = InputValidator.validate(target)
            if not validated.is_valid:
                logger.error(f"Invalid target: {', '.join(validated.errors)}")
                return

            logger.info(f"Target: [target]{validated.normalized}[/target] ({validated.target_type.value})")

            # ─── Store Target ───────────────────────────
            db_target = Target(
                domain=validated.domain,
                ip=validated.ip,
                cidr=validated.cidr,
                target_type=validated.target_type.value,
            )
            self.target_id = await self.db.insert_target(db_target)
            logger.info(f"Target ID: {self.target_id}")

            # ─── Execute Phases ─────────────────────────
            phase_map = {
                "recon": self._run_recon,
                "scan": self._run_scanning,
                "fuzz": self._run_fuzzing,
                "vuln": self._run_vuln_checks,
                "report": self._run_reporting,
            }

            for phase in phases:
                if phase not in phase_map:
                    logger.warning(f"Unknown phase: {phase}")
                    continue

                # Resume support: skip if data exists
                if resume and phase != "report":
                    if await self.db.has_phase_data(self.target_id, phase):
                        logger.info(f"Skipping phase '{phase}' (data exists, --resume enabled)")
                        self.scheduler.set_phase(phase, PhaseStatus.SKIPPED)
                        continue

                await phase_map[phase]()

            # ─── Summary ────────────────────────────────
            elapsed = time.monotonic() - self._start_time
            await self._print_summary(elapsed)

        except KeyboardInterrupt:
            logger.warning("Scan interrupted by user")
        except Exception as e:
            logger.critical(f"Engine error: {e}")
            raise
        finally:
            await self.shutdown()

    async def _run_recon(self):
        """Execute the reconnaissance phase."""
        from modules.recon.subdomains import SubdomainEnumerator
        from modules.recon.hosts import HostProber
        from modules.recon.endpoints import EndpointCollector

        target_data = await self.db.get_target(self.target_id)
        domain = target_data.get("domain", "")
        if not domain:
            logger.warning("No domain for recon, skipping subdomain enumeration")
            return

        # ─── Subdomain Enumeration ──────────────────
        enumerator = SubdomainEnumerator(self.http_client, self.config)
        subdomains = await enumerator.enumerate(domain)

        # Store subdomains
        for name in subdomains:
            sub = Subdomain(target_id=self.target_id, name=name, source="passive")
            await self.db.insert_subdomain(sub)

        logger.success(f"Found {len(subdomains)} subdomains")

        # ─── Host Probing ───────────────────────────
        prober = HostProber(self.http_client)
        sub_records = await self.db.get_subdomains(self.target_id)
        alive_hosts = await prober.probe_hosts([s["name"] for s in sub_records])

        for host_info in alive_hosts:
            # Update subdomain with alive status
            for sub in sub_records:
                if sub["name"] == host_info.get("host"):
                    await self.db.update_subdomain(
                        sub["id"],
                        is_alive=1,
                        status_code=host_info.get("status_code"),
                        title=host_info.get("title"),
                        ip=host_info.get("ip"),
                    )
                    break

        logger.success(f"Found {len(alive_hosts)} alive hosts")

        # ─── Endpoint Collection ────────────────────
        collector = EndpointCollector(self.http_client)
        alive_subs = await self.db.get_subdomains(self.target_id, alive_only=True)

        for sub in alive_subs:
            url = f"https://{sub['name']}"
            endpoints = await collector.collect(url)
            for ep_url in endpoints:
                ep = Endpoint(subdomain_id=sub["id"], url=ep_url, source="crawler")
                await self.db.insert_endpoint(ep)

        await self.db.insert_log("recon", f"Completed: {len(subdomains)} subdomains, {len(alive_hosts)} alive")

    async def _run_scanning(self):
        """Execute the scanning phase."""
        from modules.scanning.ports import PortScanner
        from modules.scanning.fingerprint import TechFingerprinter
        from modules.scanning.directories import DirectoryBruter

        alive_subs = await self.db.get_subdomains(self.target_id, alive_only=True)
        if not alive_subs:
            logger.warning("No alive hosts to scan")
            return

        # ─── Port Scanning ──────────────────────────
        scanner = PortScanner()
        for sub in alive_subs:
            ip = sub.get("ip") or sub["name"]
            open_ports = await scanner.scan(ip)
            for port_info in open_ports:
                sr = ScanResult(
                    target_id=self.target_id,
                    subdomain_id=sub["id"],
                    port=port_info["port"],
                    service=port_info.get("service"),
                    banner=port_info.get("banner"),
                    state="open",
                )
                await self.db.insert_scan_result(sr)

        # ─── Technology Fingerprinting ──────────────
        fingerprinter = TechFingerprinter(self.http_client)
        technologies = []
        for sub in alive_subs:
            url = f"https://{sub['name']}"
            techs = await fingerprinter.fingerprint(url)
            technologies.extend(techs)
            if techs:
                await self.db.update_subdomain(sub["id"], tech=",".join(techs))

        # ─── Directory Brute-force ──────────────────
        bruter = DirectoryBruter(self.http_client, self.config)
        for sub in alive_subs[:5]:  # Limit to top 5 hosts
            url = f"https://{sub['name']}"
            found_dirs = await bruter.brute(url)
            for dir_info in found_dirs:
                ep = Endpoint(
                    subdomain_id=sub["id"],
                    url=dir_info["url"],
                    status_code=dir_info.get("status_code"),
                    content_length=dir_info.get("content_length"),
                    source="dirbrute",
                )
                await self.db.insert_endpoint(ep)

        # ─── Decision Engine Analysis ───────────────
        all_endpoints = await self.db.get_all_endpoints_for_target(self.target_id)
        self.target_profile = self.decision.analyze(
            endpoints=all_endpoints,
            technologies=technologies,
            scan_results=await self.db.get_scan_results(self.target_id),
        )

        for rec in self.target_profile.recommendations:
            logger.info(f"  💡 {rec}")

        await self.db.insert_log("scanning", f"Completed scanning phase")

    async def _run_fuzzing(self):
        """Execute the fuzzing phase."""
        from modules.fuzzing.params import ParamDiscoverer
        from modules.fuzzing.endpoints import EndpointFuzzer
        from modules.fuzzing.payloads import PayloadEngine

        alive_subs = await self.db.get_subdomains(self.target_id, alive_only=True)
        if not alive_subs:
            logger.warning("No alive hosts to fuzz")
            return

        # Get fuzzing config from decision engine
        fuzz_config = {}
        if self.target_profile:
            fuzz_config = self.decision.get_fuzzing_config(self.target_profile)

        # ─── Parameter Discovery ────────────────────
        discoverer = ParamDiscoverer(self.http_client, self.config)
        for sub in alive_subs[:5]:
            url = f"https://{sub['name']}"
            params = await discoverer.discover(url)
            if params:
                for ep in await self.db.get_endpoints(sub["id"]):
                    await self.db.update_subdomain(sub["id"])  # Touch

        # ─── Endpoint Fuzzing ───────────────────────
        fuzzer = EndpointFuzzer(self.http_client, self.config)
        for sub in alive_subs[:5]:
            url = f"https://{sub['name']}"
            found = await fuzzer.fuzz(url)
            for ep_url in found:
                ep = Endpoint(subdomain_id=sub["id"], url=ep_url, source="fuzzing")
                await self.db.insert_endpoint(ep)

        await self.db.insert_log("fuzzing", "Completed fuzzing phase")

    async def _run_vuln_checks(self):
        """Execute vulnerability detection phase with auth and OOB support."""
        from modules.vulns.xss import XSSDetector
        from modules.vulns.sqli import SQLiDetector
        from modules.vulns.redirect import OpenRedirectDetector
        from modules.vulns.idor import IDORDetector
        from modules.vulns.misconfig import MisconfigDetector
        from modules.vulns.ssti import SSTIDetector
        from modules.vulns.ssrf import SSRFDetector
        from modules.vulns.nosqli import NoSQLiDetector
        from modules.vulns.csrf import CSRFDetector
        from modules.vulns.cors import CORSDetector

        alive_subs = await self.db.get_subdomains(self.target_id, alive_only=True)
        if not alive_subs:
            logger.warning("No alive hosts for vulnerability checks")
            return

        # ─── Auth: Verify session before vuln checks ───
        if self.auth_manager and self.auth_manager.is_authenticated:
            base_url = f"https://{alive_subs[0]['name']}"
            await self.auth_manager.refresh_if_needed(self.http_client, base_url)

        # ─── OOB: Start background polling ────────────
        if self.oob_client and self.oob_client.is_registered:
            await self.oob_client.start_polling()

        # Build detectors -- pass OOB client to blind-capable ones
        oob = self.oob_client  # None if OOB disabled
        detectors = [
            ("XSS", XSSDetector(self.http_client, oob_client=oob)),
            ("SQLi", SQLiDetector(self.http_client, oob_client=oob)),
            ("Open Redirect", OpenRedirectDetector(self.http_client)),
            ("IDOR", IDORDetector(self.http_client)),
            ("Misconfiguration", MisconfigDetector(self.http_client)),
            ("SSTI", SSTIDetector(self.http_client, oob_client=oob)),
            ("SSRF", SSRFDetector(self.http_client, oob_client=oob)),
            ("NoSQLi", NoSQLiDetector(self.http_client)),
            ("CSRF", CSRFDetector(self.http_client)),
            ("CORS", CORSDetector(self.http_client)),
        ]
        
        # Initialize Deduplicator
        deduplicator = FindingDeduplicator(
            max_findings=self.config.get("vulnerability", {}).get("verification", {}).get("max_findings", 50),
            min_confidence=self.config.get("vulnerability", {}).get("verification", {}).get("min_confidence", "medium")
        )

        for sub in alive_subs:
            endpoints = await self.db.get_endpoints(sub["id"])
            base_url = f"https://{sub['name']}"

            for name, detector in detectors:
                try:
                    if name == "Misconfiguration":
                        vulns = await detector.detect(base_url)
                    else:
                        urls_to_check = [ep["url"] for ep in endpoints] if endpoints else [base_url]
                        vulns = []
                        for url in urls_to_check[:20]:  # Limit per host
                            found = await detector.detect(url)
                            vulns.extend(found)

                    for v in vulns:
                        # Append metadata needed for dedup
                        v["subdomain_id"] = sub["id"]
                        v["endpoint_id"] = v.get("endpoint_id")
                        v["base_url"] = base_url
                        
                        deduplicator.add(v)
                except Exception as e:
                    logger.debug(f"Error in {name} detector for {base_url}: {e}")

        # ─── OOB: Collect blind findings ──────────────
        if self.oob_client and self.oob_client.is_registered:
            await self.oob_client.stop_polling()
            oob_wait = self.config.get("oob", {}).get("wait_timeout", 30)
            await self.oob_client.wait_for_callbacks(timeout=oob_wait)

            oob_findings = self.oob_client.get_findings()
            for v in oob_findings:
                v["subdomain_id"] = alive_subs[0]["id"]
                v["base_url"] = ""
                deduplicator.add(v)

        # ─── Finalize Findings (AI Triage & DB Insert) ───
        final_findings = deduplicator.get_findings()
        logger.info(f"Deduplicator yielded {len(final_findings)} unique findings.")
        
        for v in final_findings:
            # AI-ENHANCED Triage
            ai_triage_data = None
            if self.config.get("ai_triage"):
                logger.info(f"AI Triaging: {v['type']} at {v.get('request', '')[:50]}")
                ai_triage_data = await triage_finding(
                    vuln_type=v["type"],
                    payload=v.get("evidence", ""),
                    raw_request=v.get("request", ""),
                    raw_response=v.get("response", "")
                )
                v["ai_triage"] = ai_triage_data

            vuln = Vulnerability(
                endpoint_id=v.get("endpoint_id"),
                subdomain_id=v.get("subdomain_id"),
                target_id=self.target_id,
                vuln_type=v["type"],
                severity=v["severity"],
                title=v.get("title", ""),
                description=v.get("description", ""),
                evidence=v.get("evidence", ""),
                request_data=str(v.get("request", "")),
                response_data=str(v.get("response", ""))[:5000],
                reproduction=v.get("reproduction", ""),
                confidence=v.get("confidence", "medium"),
                verification_method=v.get("verification_method", ""),
                ai_triage=json.dumps(ai_triage_data) if ai_triage_data else None,
            )
            await self.db.insert_vulnerability(vuln)
            logger.finding(v["severity"], v["type"], v.get("base_url", ""), v.get("title", ""))

        await self.db.insert_log("vulns", "Completed vulnerability checks")

    async def _run_reporting(self):
        """Generate scan reports."""
        from reports.generator import ReportGenerator

        generator = ReportGenerator(self.db, self.config)
        output_dir = self.config.get("reporting", {}).get("output_dir", "reports/output")

        await generator.generate(self.target_id, output_dir)
        logger.success(f"Reports generated in {output_dir}/")

    async def _print_summary(self, elapsed: float):
        """Print final scan summary."""
        from rich.table import Table
        from utils.logger import console

        stats = await self.db.get_stats(self.target_id)

        console.print(f"\n[bold cyan]{'━' * 60}[/bold cyan]")
        console.print("[bold cyan]  ▶ SCAN SUMMARY[/bold cyan]")
        console.print(f"[bold cyan]{'━' * 60}[/bold cyan]\n")

        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Metric", style="cyan")
        table.add_column("Count", style="white", justify="right")

        table.add_row("Subdomains", str(stats.get("subdomains", 0)))
        table.add_row("Endpoints", str(stats.get("endpoints", 0)))
        table.add_row("Open Ports", str(stats.get("scan_results", 0)))
        table.add_row("Vulnerabilities", str(stats.get("vulnerabilities", 0)))

        console.print(table)

        # Vulnerability breakdown
        breakdown = stats.get("vuln_breakdown", {})
        if breakdown:
            console.print("\n[bold]Vulnerability Breakdown:[/bold]")
            for sev, count in breakdown.items():
                colors = {"critical": "bold white on red", "high": "red",
                          "medium": "yellow", "low": "blue", "info": "cyan"}
                color = colors.get(sev, "white")
                console.print(f"  [{color}]{sev.upper():12s}[/{color}] → {count}")

        console.print(f"\n[dim]Scan completed in {elapsed:.1f}s[/dim]\n")

        # Phase summary
        phase_summary = self.scheduler.summary
        if phase_summary:
            console.print("[bold]Phase Results:[/bold]")
            for phase, info in phase_summary.items():
                status_icon = {"completed": "✓", "failed": "✗", "skipped": "⊘"}.get(info["status"], "?")
                console.print(f"  {status_icon} {phase}: {info['status']} ({info['duration']})")
