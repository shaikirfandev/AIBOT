FROM python:3.12-slim

LABEL maintainer="BBHunter Team"
LABEL description="Bug Bounty Automation Suite"

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl dnsutils nmap whois && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python deps
COPY pyproject.toml ./
RUN pip install --no-cache-dir -e ".[dev]" 2>/dev/null || pip install --no-cache-dir .

# Copy source
COPY . .

# Create data directory
RUN mkdir -p /app/data/models /app/data/reports /app/data/logs

# Non-root user
RUN useradd -m -s /bin/bash bbhunter && chown -R bbhunter:bbhunter /app
USER bbhunter

EXPOSE 8000

ENTRYPOINT ["python", "-m", "bbhunter.cli"]
CMD ["dashboard", "--host", "0.0.0.0"]
