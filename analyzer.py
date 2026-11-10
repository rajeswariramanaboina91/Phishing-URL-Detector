
from urllib.parse import urlparse
import re
import ipaddress


def analyze_url(url):
    url = url.strip()

    if not url:
        return {"error": "Please enter a URL"}

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        parsed = urlparse(url)
        domain = parsed.hostname

        if not domain:
            return {"error": "Invalid URL. Please enter a valid domain."}

        domain = domain.lower()

        # Validate IP addresses
        is_ip = False
        try:
            ipaddress.ip_address(domain)
            is_ip = True
        except ValueError:
            pass

        # Basic domain validation
        if not is_ip:
            if "." not in domain or len(domain) > 253:
                return {"error": "Invalid domain name."}

            labels = domain.rstrip(".").split(".")
            if any(
                not label or len(label) > 63
                or not re.fullmatch(r"[a-z0-9-]+", label)
                or label.startswith("-") or label.endswith("-")
                for label in labels
            ):
                return {"error": "Invalid domain name."}

        score = 0
        reasons = []
        checks = []

        def add_check(name, passed, message):
            checks.append({
                "name": name,
                "status": "Passed" if passed else "Warning",
                "message": message
            })

        # HTTPS check
        if parsed.scheme == "https":
            add_check("HTTPS", True, "HTTPS protocol detected")
        else:
            score += 20
            reasons.append("No HTTPS connection")
            add_check("HTTPS", False, "No HTTPS connection")

        # IP address check
        if is_ip:
            score += 25
            reasons.append("URL uses an IP address")
            add_check("IP Address", False, "IP address used instead of domain")
        else:
            add_check("IP Address", True, "Domain name detected")

        # Suspicious keywords
        suspicious_keywords = [
            "login", "verify", "verification", "secure",
            "account", "update", "password", "bank",
            "confirm", "signin", "wallet", "recover"
        ]

        found_keywords = [
            word for word in suspicious_keywords
            if word in url.lower()
        ]

        if found_keywords:
            score += min(len(found_keywords) * 10, 30)
            reasons.append(
                "Suspicious keywords: " + ", ".join(found_keywords)
            )
            add_check("Keywords", False, "Suspicious words detected")
        else:
            add_check("Keywords", True, "No suspicious keywords detected")

        # URL length
        if len(url) > 75:
            score += 15
            reasons.append("URL is unusually long")
            add_check("URL Length", False, "Unusually long URL")
        else:
            add_check("URL Length", True, "URL length looks normal")

        # Special characters
        special_count = sum(
            1 for char in url if char in ["@", "%", "-", "_", "="]
        )

        if special_count >= 5:
            score += 10
            reasons.append("Many special characters")
            add_check("Special Characters", False, "Many special characters")
        else:
            add_check("Special Characters", True, "No excessive special characters")

        # Suspicious domain patterns
        if "-" in domain:
            score += 5
            reasons.append("Domain contains hyphens")
            add_check("Domain Pattern", False, "Hyphen found in domain")
        else:
            add_check("Domain Pattern", True, "No hyphen pattern detected")

        # URL contains username/password information
        if parsed.username or parsed.password:
            score += 20
            reasons.append("URL contains embedded credentials")
            add_check("URL Credentials", False, "Credentials found in URL")
        else:
            add_check("URL Credentials", True, "No embedded credentials")

        score = min(score, 100)

        if score >= 50:
            result = "PHISHING"
            risk_level = "High"
        elif score >= 25:
            result = "SUSPICIOUS"
            risk_level = "Medium"
        else:
            result = "LOW RISK"
            risk_level = "Low"

        if not reasons:
            reasons.append("No suspicious patterns detected by basic checks")

        return {
            "url": url,
            "domain": domain,
            "protocol": parsed.scheme.upper(),
            "length": len(url),
            "score": score,
            "result": result,
            "risk_level": risk_level,
            "reasons": reasons,
            "checks": checks
        }

    except (ValueError, UnicodeError):
        return {"error": "Unable to analyze this URL"}
