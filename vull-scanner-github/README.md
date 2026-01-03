# VULL Scanner

<p align="center">
  <img src="docs/banner.png" alt="VULL Scanner" width="600">
</p>

<p align="center">
  <strong>AI-Powered Vulnerability Scanner for Web Applications</strong>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#api">API</a> •
  <a href="#architecture">Architecture</a>
</p>

---

## Overview

VULL Scanner is an intelligent vulnerability scanner that leverages **LLM-powered reconnaissance** and professional security tools to discover and test web application vulnerabilities. Built with a microservices architecture, it combines AI-driven login discovery with traditional security scanning techniques.

### Key Highlights

- **AI-Powered Discovery**: Uses GPT-4 with tool-calling (ReAct pattern) to intelligently crawl and discover login endpoints
- **Technology Detection**: Automatically identifies CMS, frameworks, and server technologies
- **Smart Wordlist Selection**: Dynamically selects SecLists wordlists based on detected technologies
- **Parallel Testing**: Adaptive thread pooling for high-performance credential testing
- **REST API**: Full-featured async API with rate limiting and JWT authentication
- **Production Ready**: Prometheus metrics, structured logging, and Celery job queue

---

## Features

### Vulnerability Detection
| Type | Description |
|------|-------------|
| **Credential Testing** | Tests for default/weak credentials with technology-specific wordlists |
| **SQL Injection** | Integration with sqlmap for automated SQLi detection |
| **Exposed Endpoints** | Uses ffuf for directory/file discovery |
| **Subdomain Enumeration** | Amass integration for attack surface discovery |

### Security Features
| Feature | Description |
|---------|-------------|
| **SSRF Protection** | Blocks requests to internal/private IP ranges |
| **Password Masking** | Credentials masked in logs and output |
| **SSL Verification** | Enabled by default, configurable per-scan |
| **Rate Limiting** | Per-API-key and global concurrent limits |
| **Input Validation** | Strict URL validation with RFC compliance |

### Architecture Features
| Component | Technology |
|-----------|------------|
| **Workflow Engine** | LangGraph state machine |
| **LLM Integration** | OpenAI GPT-4 with tool calling |
| **API Framework** | FastAPI with async support |
| **Database** | PostgreSQL with SQLAlchemy ORM |
| **Job Queue** | Celery with Redis backend |
| **Metrics** | Prometheus + custom middleware |

---

## Installation

### Prerequisites

- Python 3.11+
- PostgreSQL (for API mode)
- Redis (for async scanning)
- External tools (optional): nmap, ffuf, sqlmap, amass

### Quick Start

```bash
# Clone the repository
git clone https://github.com/yourusername/vull-scanner.git
cd vull-scanner

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Set up environment variables
export OPENAI_API_KEY="your-api-key"

# Run a scan
python -m vull_scanner https://example.com
```

### Full Installation (with API)

```bash
# Install with all dependencies
pip install -e ".[dev]"

# Set up database
export DATABASE_URL="postgresql://user:pass@localhost/vull_scanner"

# Start Redis
docker run -d -p 6379:6379 redis:7

# Run database migrations
alembic upgrade head

# Start the API
uvicorn vull_scanner.api.main:app --reload

# Start Celery worker (separate terminal)
celery -A vull_scanner.worker worker -l info
```

---

## Usage

### CLI Mode

```bash
# Basic scan
python -m vull_scanner https://target.com

# Verbose output with all details
python -m vull_scanner --verbose https://target.com

# Allow scanning private IPs (for internal testing)
python -m vull_scanner --allow-private https://192.168.1.1

# Skip SSL verification
python -m vull_scanner --skip-ssl-verify https://target.com

# Show passwords in output (use with caution)
python -m vull_scanner --show-passwords https://target.com
```

### API Mode

```bash
# Health check
curl http://localhost:8000/health

# Create a scan (requires API key)
curl -X POST http://localhost:8000/api/v1/scans \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com"}'

# Get scan status
curl http://localhost:8000/api/v1/scans/{scan_id} \
  -H "X-API-Key: your-api-key"

# Get scan results
curl http://localhost:8000/api/v1/scans/{scan_id}/results \
  -H "X-API-Key: your-api-key"
```

---

## API

### Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/scans` | Create new scan |
| `GET` | `/api/v1/scans` | List all scans |
| `GET` | `/api/v1/scans/{id}` | Get scan status |
| `GET` | `/api/v1/scans/{id}/results` | Get scan results |
| `DELETE` | `/api/v1/scans/{id}` | Cancel scan |
| `GET` | `/health` | Health check |
| `GET` | `/metrics` | Prometheus metrics |

### Authentication

The API supports two authentication methods:

1. **API Key**: Include `X-API-Key` header
2. **JWT Token**: Include `Authorization: Bearer <token>` header

### Rate Limits

| Limit | Value |
|-------|-------|
| Requests per minute | 60 |
| Scans per day | 100 |
| Concurrent scans | 10 |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         VULL Scanner                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐  │
│  │  Input   │───▶│   Port   │───▶│  Login   │───▶│  Creds   │  │
│  │  Node    │    │ Scanner  │    │  Finder  │    │  Tester  │  │
│  └──────────┘    └──────────┘    └────┬─────┘    └──────────┘  │
│                                       │                         │
│                                       ▼                         │
│                              ┌──────────────┐                   │
│                              │   LLM Agent  │                   │
│                              │   (GPT-4o)   │                   │
│                              └──────┬───────┘                   │
│                                     │                           │
│                    ┌────────────────┼────────────────┐          │
│                    ▼                ▼                ▼          │
│              ┌──────────┐    ┌──────────┐    ┌──────────┐      │
│              │   nmap   │    │   ffuf   │    │  amass   │      │
│              └──────────┘    └──────────┘    └──────────┘      │
│                                                                  │
├─────────────────────────────────────────────────────────────────┤
│                         API Layer                                │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐  │
│  │ FastAPI  │───▶│  Celery  │───▶│  Redis   │    │ Postgres │  │
│  └──────────┘    └──────────┘    └──────────┘    └──────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

### Workflow

1. **Input Validation**: URL validation with SSRF protection
2. **Port Scanning**: Check for open HTTP/HTTPS ports
3. **Login Discovery**: AI-powered crawling to find login forms
4. **Technology Detection**: Identify CMS, frameworks, servers
5. **Wordlist Selection**: Choose appropriate SecLists based on tech stack
6. **Credential Testing**: Parallel testing with adaptive threading
7. **Result Aggregation**: Compile and report findings

---

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `OPENAI_API_KEY` | OpenAI API key (required) | - |
| `DATABASE_URL` | PostgreSQL connection URL | `sqlite:///./vull_scanner.db` |
| `REDIS_URL` | Redis connection URL | `redis://localhost:6379/0` |
| `VULL_MAX_THREADS` | Maximum concurrent threads | `50` |
| `VULL_HTTP_TIMEOUT` | HTTP request timeout (seconds) | `10` |
| `VULL_SKIP_SSL_VERIFY` | Skip SSL verification | `false` |
| `JWT_SECRET_KEY` | JWT signing key | - |

### Configuration File

Create `config.yaml`:

```yaml
threading:
  min_threads: 5
  max_threads: 50

rate_limit:
  request_delay: 0.1
  max_requests_per_minute: 600

timeout:
  http_timeout: 10.0
  tool_timeout: 300.0

security:
  verify_ssl: true
  allow_private_ips: false
```

---

## Testing

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=vull_scanner --cov-report=html

# Run specific test file
pytest tests/test_validation.py -v
```

---

## Project Structure

```
vull-scanner/
├── vull_scanner/
│   ├── api/                 # REST API
│   │   ├── routes/          # API endpoints
│   │   ├── models/          # Pydantic models
│   │   ├── auth.py          # Authentication
│   │   ├── metrics.py       # Prometheus metrics
│   │   └── rate_limiter.py  # Rate limiting
│   ├── db/                  # Database layer
│   │   ├── models.py        # SQLAlchemy models
│   │   └── repositories.py  # Data access
│   ├── nodes/               # LangGraph nodes
│   │   ├── input_node.py    # Input validation
│   │   ├── port_scanner.py  # Port scanning
│   │   ├── login_finder.py  # AI login discovery
│   │   └── credential_tester.py
│   ├── utils/               # Utilities
│   │   ├── validation.py    # URL/input validation
│   │   ├── http_client.py   # HTTP client pool
│   │   └── logging.py       # Structured logging
│   ├── graph.py             # LangGraph workflow
│   ├── state.py             # State schema
│   ├── tools.py             # LLM tools
│   ├── config.py            # Configuration
│   └── worker.py            # Celery worker
├── tests/                   # Test suite
├── docs/                    # Documentation
├── requirements.txt
└── pyproject.toml
```

---

## Security Considerations

This tool is intended for **authorized security testing only**. Always:

- Obtain written permission before scanning any target
- Respect rate limits and avoid overwhelming targets
- Follow responsible disclosure practices
- Comply with applicable laws and regulations

---

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Acknowledgments

- [LangGraph](https://github.com/langchain-ai/langgraph) - Workflow orchestration
- [SecLists](https://github.com/danielmiessler/SecLists) - Security wordlists
- [FastAPI](https://fastapi.tiangolo.com/) - API framework
- OpenAI GPT-4 - AI-powered reconnaissance

---

<p align="center">
  Made with security in mind
</p>
