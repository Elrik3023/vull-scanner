"""Nmap scanner node for port and service detection."""

import xml.etree.ElementTree as ET
import time
from vull_scanner.state import ScannerState, NmapResult, PortInfo, DetectedTechnology
from vull_scanner.utils.tool_runner import run_command, ToolNotFoundError, ToolExecutionError


def nmap_scanner_node(state: ScannerState) -> dict:
    """Run Nmap scan on target for port and service detection.

    Uses Nmap with service version detection (-sV) and default scripts (-sC).
    Outputs XML for easy parsing.

    Args:
        state: Current scanner state with target_url.

    Returns:
        Updated state with nmap_result and detected_technologies.
    """
    target = state["target_url"]
    errors = list(state.get("errors", []))

    print(f"\n[*] Running Nmap scan on {target}...")

    try:
        start_time = time.time()

        # Run Nmap with:
        # -sV: Service/version detection
        # -sC: Default scripts
        # -T4: Aggressive timing (faster)
        # -oX -: XML output to stdout
        # --top-ports 1000: Scan top 1000 ports
        result = run_command(
            [
                "nmap",
                "-sV",
                "-sC",
                "-T4",
                "--top-ports", "1000",
                "-oX", "-",
                target,
            ],
            timeout=600,  # 10 minute timeout
        )

        scan_time = time.time() - start_time

        if not result.success:
            errors.append(f"Nmap scan failed: {result.stderr}")
            print(f"[!] Nmap scan failed: {result.stderr[:200]}")
            return {
                "nmap_result": None,
                "errors": errors,
                "current_phase": "complete",
            }

        # Parse the XML output
        nmap_result = parse_nmap_xml(result.stdout, target, scan_time)

        # Detect technologies from service versions
        technologies = detect_technologies_from_nmap(nmap_result)

        # Print summary
        print(f"[+] Nmap scan completed in {scan_time:.1f}s")
        print(f"    Open ports: {len(nmap_result.open_ports)}")
        for port in nmap_result.open_ports:
            version_info = f" ({port.version})" if port.version else ""
            print(f"      - {port.port}/{port.protocol} {port.service}{version_info}")

        if technologies:
            print(f"    Detected technologies: {len(technologies)}")
            for tech in technologies:
                print(f"      - {tech.name}" + (f" {tech.version}" if tech.version else ""))

        return {
            "nmap_result": nmap_result,
            "detected_technologies": technologies,
            "current_phase": "ffuf",
        }

    except ToolNotFoundError as e:
        errors.append(str(e))
        print(f"[!] {e}")
        return {
            "nmap_result": None,
            "errors": errors,
            "current_phase": "complete",
        }
    except ToolExecutionError as e:
        errors.append(str(e))
        print(f"[!] {e}")
        return {
            "nmap_result": None,
            "errors": errors,
            "current_phase": "complete",
        }


def parse_nmap_xml(xml_output: str, target: str, scan_time: float) -> NmapResult:
    """Parse Nmap XML output into NmapResult.

    Args:
        xml_output: Raw XML string from Nmap.
        target: Target that was scanned.
        scan_time: How long the scan took.

    Returns:
        Parsed NmapResult.
    """
    open_ports = []
    os_detection = None
    scripts_output = {}

    try:
        root = ET.fromstring(xml_output)

        # Find host element
        host = root.find(".//host")
        if host is None:
            return NmapResult(
                target=target,
                open_ports=[],
                raw_output=xml_output[:5000],
                scan_time=scan_time,
            )

        # Parse ports
        for port_elem in host.findall(".//port"):
            state_elem = port_elem.find("state")
            service_elem = port_elem.find("service")

            if state_elem is not None and state_elem.get("state") == "open":
                port_info = PortInfo(
                    port=int(port_elem.get("portid", 0)),
                    protocol=port_elem.get("protocol", "tcp"),
                    state="open",
                    service=service_elem.get("name", "unknown") if service_elem is not None else "unknown",
                    version=service_elem.get("version", "") if service_elem is not None else "",
                    product=service_elem.get("product", "") if service_elem is not None else "",
                )
                open_ports.append(port_info)

            # Parse script outputs for this port
            for script in port_elem.findall(".//script"):
                script_id = script.get("id", "unknown")
                script_output = script.get("output", "")
                scripts_output[f"{port_info.port}/{script_id}"] = script_output

        # Parse OS detection
        os_elem = host.find(".//osmatch")
        if os_elem is not None:
            os_detection = os_elem.get("name", "")

    except ET.ParseError as e:
        print(f"[!] Failed to parse Nmap XML: {e}")

    return NmapResult(
        target=target,
        open_ports=open_ports,
        os_detection=os_detection,
        scripts_output=scripts_output,
        raw_output=xml_output[:5000],  # Truncate for storage
        scan_time=scan_time,
    )


def detect_technologies_from_nmap(nmap_result: NmapResult) -> list[DetectedTechnology]:
    """Detect technologies from Nmap service versions.

    Args:
        nmap_result: Parsed Nmap results.

    Returns:
        List of detected technologies.
    """
    technologies = []
    seen = set()

    for port in nmap_result.open_ports:
        service_lower = port.service.lower()
        product_lower = port.product.lower()
        version = port.version

        # Web servers
        if "apache" in product_lower:
            if "apache" not in seen:
                seen.add("apache")
                technologies.append(DetectedTechnology(
                    name="apache",
                    confidence="high",
                    evidence=f"Port {port.port}: {port.product} {version}",
                    version=version,
                ))
        elif "nginx" in product_lower:
            if "nginx" not in seen:
                seen.add("nginx")
                technologies.append(DetectedTechnology(
                    name="nginx",
                    confidence="high",
                    evidence=f"Port {port.port}: {port.product} {version}",
                    version=version,
                ))
        elif "iis" in product_lower or "microsoft-iis" in service_lower:
            if "iis" not in seen:
                seen.add("iis")
                technologies.append(DetectedTechnology(
                    name="iis",
                    confidence="high",
                    evidence=f"Port {port.port}: {port.product} {version}",
                    version=version,
                ))

        # Application servers
        if "tomcat" in product_lower:
            if "tomcat" not in seen:
                seen.add("tomcat")
                technologies.append(DetectedTechnology(
                    name="tomcat",
                    confidence="high",
                    evidence=f"Port {port.port}: {port.product} {version}",
                    version=version,
                ))

        # Databases
        if "mysql" in service_lower or "mysql" in product_lower:
            if "mysql" not in seen:
                seen.add("mysql")
                technologies.append(DetectedTechnology(
                    name="database",
                    confidence="high",
                    evidence=f"Port {port.port}: MySQL {version}",
                    version=version,
                ))
        elif "postgresql" in service_lower or "postgres" in product_lower:
            if "postgresql" not in seen:
                seen.add("postgresql")
                technologies.append(DetectedTechnology(
                    name="database",
                    confidence="high",
                    evidence=f"Port {port.port}: PostgreSQL {version}",
                    version=version,
                ))

        # SSH
        if service_lower == "ssh":
            if "ssh" not in seen:
                seen.add("ssh")
                technologies.append(DetectedTechnology(
                    name="ssh",
                    confidence="high",
                    evidence=f"Port {port.port}: {port.product} {version}",
                    version=version,
                ))

        # FTP
        if service_lower == "ftp":
            if "ftp" not in seen:
                seen.add("ftp")
                technologies.append(DetectedTechnology(
                    name="ftp",
                    confidence="high",
                    evidence=f"Port {port.port}: {port.product} {version}",
                    version=version,
                ))

    return technologies


def get_http_ports(nmap_result: NmapResult) -> list[tuple[int, str]]:
    """Get list of HTTP/HTTPS ports from Nmap results.

    Args:
        nmap_result: Parsed Nmap results.

    Returns:
        List of (port, protocol) tuples where protocol is 'http' or 'https'.
    """
    http_ports = []

    for port in nmap_result.open_ports:
        service = port.service.lower()
        if "http" in service:
            if "https" in service or "ssl" in service or port.port == 443:
                http_ports.append((port.port, "https"))
            else:
                http_ports.append((port.port, "http"))
        elif port.port in [80, 8080, 8000, 8888]:
            http_ports.append((port.port, "http"))
        elif port.port in [443, 8443]:
            http_ports.append((port.port, "https"))

    return http_ports
