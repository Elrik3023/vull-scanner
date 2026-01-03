"""SecLists wordlist discovery and dynamic selection utilities."""

import os
from pathlib import Path
from dataclasses import dataclass, field

# Common SecLists installation locations
SECLISTS_PATHS = [
    "/usr/share/seclists",
    os.path.expanduser("~/SecLists"),
    "/opt/seclists",
    "/usr/share/wordlists/seclists",
]

# Default fallback credentials if SecLists not found
DEFAULT_USERNAMES = ["admin", "administrator", "root", "user", "test", "guest", "demo"]
DEFAULT_PASSWORDS = ["password", "123456", "admin", "root", "letmein", "welcome", "password123"]


@dataclass
class WordlistCategory:
    """Category of wordlists with associated files."""
    name: str
    description: str
    username_patterns: list[str] = field(default_factory=list)
    password_patterns: list[str] = field(default_factory=list)


# Technology to wordlist mapping
TECHNOLOGY_WORDLIST_MAP: dict[str, WordlistCategory] = {
    "wordpress": WordlistCategory(
        name="WordPress",
        description="WordPress CMS default and common credentials",
        username_patterns=[
            "Usernames/top-usernames-shortlist.txt",
            "Usernames/cirt-default-usernames.txt",
        ],
        password_patterns=[
            "Passwords/Default-Credentials/default-passwords.txt",
            "Passwords/Common-Credentials/10k-most-common.txt",
            "Passwords/Leaked-Databases/rockyou-10.txt",
        ],
    ),
    "joomla": WordlistCategory(
        name="Joomla",
        description="Joomla CMS credentials",
        username_patterns=[
            "Usernames/top-usernames-shortlist.txt",
            "Usernames/cirt-default-usernames.txt",
        ],
        password_patterns=[
            "Passwords/Default-Credentials/default-passwords.txt",
            "Passwords/Common-Credentials/10k-most-common.txt",
        ],
    ),
    "drupal": WordlistCategory(
        name="Drupal",
        description="Drupal CMS credentials",
        username_patterns=[
            "Usernames/top-usernames-shortlist.txt",
        ],
        password_patterns=[
            "Passwords/Common-Credentials/10k-most-common.txt",
        ],
    ),
    "tomcat": WordlistCategory(
        name="Apache Tomcat",
        description="Tomcat manager default credentials",
        username_patterns=[
            "Usernames/top-usernames-shortlist.txt",
            "Passwords/Default-Credentials/tomcat-betterdefaultpasslist.txt",
        ],
        password_patterns=[
            "Passwords/Default-Credentials/tomcat-betterdefaultpasslist.txt",
            "Passwords/Default-Credentials/default-passwords.txt",
        ],
    ),
    "phpmyadmin": WordlistCategory(
        name="phpMyAdmin",
        description="phpMyAdmin/MySQL credentials",
        username_patterns=[
            "Usernames/top-usernames-shortlist.txt",
        ],
        password_patterns=[
            "Passwords/Default-Credentials/mysql-betterdefaultpasslist.txt",
            "Passwords/Default-Credentials/default-passwords.txt",
            "Passwords/Common-Credentials/10k-most-common.txt",
        ],
    ),
    "ftp": WordlistCategory(
        name="FTP",
        description="FTP service credentials",
        username_patterns=[
            "Usernames/top-usernames-shortlist.txt",
            "Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt",
        ],
        password_patterns=[
            "Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt",
            "Passwords/Default-Credentials/default-passwords.txt",
        ],
    ),
    "ssh": WordlistCategory(
        name="SSH",
        description="SSH service credentials",
        username_patterns=[
            "Usernames/top-usernames-shortlist.txt",
            "Passwords/Default-Credentials/ssh-betterdefaultpasslist.txt",
        ],
        password_patterns=[
            "Passwords/Default-Credentials/ssh-betterdefaultpasslist.txt",
            "Passwords/Common-Credentials/10k-most-common.txt",
        ],
    ),
    "router": WordlistCategory(
        name="Router/Network Device",
        description="Router and network device defaults",
        username_patterns=[
            "Passwords/Default-Credentials/router-betterdefaultpasslist.txt",
        ],
        password_patterns=[
            "Passwords/Default-Credentials/router-betterdefaultpasslist.txt",
            "Passwords/Default-Credentials/default-passwords.txt",
        ],
    ),
    "cisco": WordlistCategory(
        name="Cisco",
        description="Cisco device credentials",
        username_patterns=[
            "Usernames/top-usernames-shortlist.txt",
        ],
        password_patterns=[
            "Passwords/Default-Credentials/cisco-betterdefaultpasslist.txt",
            "Passwords/Default-Credentials/default-passwords.txt",
        ],
    ),
    "database": WordlistCategory(
        name="Database",
        description="Database service credentials",
        username_patterns=[
            "Usernames/top-usernames-shortlist.txt",
        ],
        password_patterns=[
            "Passwords/Default-Credentials/postgres-betterdefaultpasslist.txt",
            "Passwords/Default-Credentials/mssql-betterdefaultpasslist.txt",
            "Passwords/Default-Credentials/mysql-betterdefaultpasslist.txt",
            "Passwords/Default-Credentials/oracle-betterdefaultpasslist.txt",
            "Passwords/Default-Credentials/default-passwords.txt",
        ],
    ),
    "generic": WordlistCategory(
        name="Generic Web Application",
        description="Common web application credentials",
        username_patterns=[
            "Usernames/top-usernames-shortlist.txt",
            "Usernames/cirt-default-usernames.txt",
            "Usernames/Names/names.txt",
        ],
        password_patterns=[
            "Passwords/Common-Credentials/10k-most-common.txt",
            "Passwords/Common-Credentials/best1050.txt",
            "Passwords/Common-Credentials/top-passwords-shortlist.txt",
            "Passwords/Default-Credentials/default-passwords.txt",
            "Passwords/Leaked-Databases/rockyou-10.txt",
            "Passwords/Leaked-Databases/rockyou-15.txt",
        ],
    ),
}


def find_seclists_path() -> Path | None:
    """Find the SecLists installation directory."""
    for path in SECLISTS_PATHS:
        p = Path(path)
        if p.exists() and p.is_dir():
            return p
    return None


def discover_available_wordlists() -> dict[str, list[str]]:
    """Discover all available wordlists in SecLists.

    Returns:
        Dictionary with 'usernames' and 'passwords' keys containing lists of available files.
    """
    seclists = find_seclists_path()
    if not seclists:
        return {"usernames": [], "passwords": []}

    available = {"usernames": [], "passwords": []}

    # Discover username wordlists
    usernames_dir = seclists / "Usernames"
    if usernames_dir.exists():
        for txt_file in usernames_dir.rglob("*.txt"):
            available["usernames"].append(str(txt_file.relative_to(seclists)))

    # Discover password wordlists
    passwords_dir = seclists / "Passwords"
    if passwords_dir.exists():
        for txt_file in passwords_dir.rglob("*.txt"):
            # Skip very large files (> 50MB)
            if txt_file.stat().st_size < 50 * 1024 * 1024:
                available["passwords"].append(str(txt_file.relative_to(seclists)))

    return available


def get_wordlists_for_technologies(
    technologies: list[str],
    max_username_files: int = 5,
    max_password_files: int = 10,
) -> tuple[list[str], list[str], str]:
    """Get appropriate wordlists based on detected technologies.

    Args:
        technologies: List of detected technology names (lowercase).
        max_username_files: Maximum number of username files to return.
        max_password_files: Maximum number of password files to return.

    Returns:
        Tuple of (username_files, password_files, reasoning).
    """
    seclists = find_seclists_path()
    if not seclists:
        return [], [], "SecLists not found, using defaults"

    username_files = []
    password_files = []
    matched_categories = []

    # Collect wordlists for each detected technology
    for tech in technologies:
        tech_lower = tech.lower()

        # Direct match
        if tech_lower in TECHNOLOGY_WORDLIST_MAP:
            category = TECHNOLOGY_WORDLIST_MAP[tech_lower]
            matched_categories.append(category.name)

            for pattern in category.username_patterns:
                full_path = seclists / pattern
                if full_path.exists() and str(full_path) not in username_files:
                    username_files.append(str(full_path))

            for pattern in category.password_patterns:
                full_path = seclists / pattern
                if full_path.exists() and str(full_path) not in password_files:
                    password_files.append(str(full_path))

        # Partial matches
        else:
            for key, category in TECHNOLOGY_WORDLIST_MAP.items():
                if key in tech_lower or tech_lower in key:
                    matched_categories.append(category.name)
                    for pattern in category.username_patterns:
                        full_path = seclists / pattern
                        if full_path.exists() and str(full_path) not in username_files:
                            username_files.append(str(full_path))
                    for pattern in category.password_patterns:
                        full_path = seclists / pattern
                        if full_path.exists() and str(full_path) not in password_files:
                            password_files.append(str(full_path))

    # Always add generic wordlists as fallback
    if not matched_categories or "generic" not in [t.lower() for t in technologies]:
        generic = TECHNOLOGY_WORDLIST_MAP["generic"]
        for pattern in generic.username_patterns:
            full_path = seclists / pattern
            if full_path.exists() and str(full_path) not in username_files:
                username_files.append(str(full_path))
        for pattern in generic.password_patterns:
            full_path = seclists / pattern
            if full_path.exists() and str(full_path) not in password_files:
                password_files.append(str(full_path))

    # Limit the number of files
    username_files = username_files[:max_username_files]
    password_files = password_files[:max_password_files]

    # Build reasoning
    if matched_categories:
        reasoning = f"Selected wordlists for: {', '.join(set(matched_categories))}. "
    else:
        reasoning = "No specific technology matched, using generic wordlists. "

    reasoning += f"Using {len(username_files)} username files and {len(password_files)} password files."

    return username_files, password_files, reasoning


def load_wordlist(path: str, limit: int = 1000) -> list[str]:
    """Load a wordlist file with a limit.

    Args:
        path: Path to the wordlist file.
        limit: Maximum number of words to load.

    Returns:
        List of words from the file.
    """
    words = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                word = line.strip()
                if word and not word.startswith("#"):
                    words.append(word)
                    if len(words) >= limit:
                        break
    except OSError as e:
        print(f"[!] Error reading wordlist {path}: {e}")
        return []

    return words


def load_multiple_wordlists(paths: list[str], limit_per_file: int = 500, total_limit: int = 2000) -> list[str]:
    """Load multiple wordlist files and combine them.

    Args:
        paths: List of paths to wordlist files.
        limit_per_file: Maximum words to load from each file.
        total_limit: Maximum total words to return.

    Returns:
        Combined list of unique words.
    """
    all_words = []
    seen = set()

    for path in paths:
        if not Path(path).exists():
            continue

        words = load_wordlist(path, limit_per_file)
        for word in words:
            if word not in seen:
                seen.add(word)
                all_words.append(word)
                if len(all_words) >= total_limit:
                    return all_words

    return all_words


def load_usernames(limit: int = 100) -> list[str]:
    """Load usernames from SecLists (legacy function for backward compatibility).

    Args:
        limit: Maximum number of usernames to load.

    Returns:
        List of usernames.
    """
    seclists = find_seclists_path()
    if not seclists:
        print("[!] SecLists not found, using default usernames")
        return DEFAULT_USERNAMES[:limit]

    # Use generic wordlists
    username_files, _, _ = get_wordlists_for_technologies(["generic"], max_username_files=3)

    if username_files:
        return load_multiple_wordlists(username_files, limit_per_file=limit, total_limit=limit)

    return DEFAULT_USERNAMES[:limit]


def load_passwords(limit: int = 100) -> list[str]:
    """Load passwords from SecLists (legacy function for backward compatibility).

    Args:
        limit: Maximum number of passwords to load.

    Returns:
        List of passwords.
    """
    seclists = find_seclists_path()
    if not seclists:
        print("[!] SecLists not found, using default passwords")
        return DEFAULT_PASSWORDS[:limit]

    # Use generic wordlists
    _, password_files, _ = get_wordlists_for_technologies(["generic"], max_password_files=5)

    if password_files:
        return load_multiple_wordlists(password_files, limit_per_file=limit // 2, total_limit=limit)

    return DEFAULT_PASSWORDS[:limit]


def list_available_categories() -> list[str]:
    """List all available technology categories.

    Returns:
        List of category names.
    """
    return list(TECHNOLOGY_WORDLIST_MAP.keys())


def get_category_info(category: str) -> dict | None:
    """Get information about a specific category.

    Args:
        category: Category name.

    Returns:
        Dictionary with category info or None if not found.
    """
    if category.lower() not in TECHNOLOGY_WORDLIST_MAP:
        return None

    cat = TECHNOLOGY_WORDLIST_MAP[category.lower()]
    seclists = find_seclists_path()

    available_usernames = []
    available_passwords = []

    if seclists:
        for pattern in cat.username_patterns:
            full_path = seclists / pattern
            if full_path.exists():
                available_usernames.append(pattern)

        for pattern in cat.password_patterns:
            full_path = seclists / pattern
            if full_path.exists():
                available_passwords.append(pattern)

    return {
        "name": cat.name,
        "description": cat.description,
        "available_username_files": available_usernames,
        "available_password_files": available_passwords,
    }
