FROM python:3.12-slim

LABEL maintainer="BBHunter Team"
LABEL description="Bug Bounty Automation Suite"

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl dnsutils nmap whois wget && \
    rm -rf /var/lib/apt/lists/*

# Install Go (for recon tools)
ENV GOPATH=/usr/local/go
ENV PATH="$GOPATH/bin:/usr/local/go/bin:$PATH"
RUN wget -qO- https://go.dev/dl/go1.22.4.linux-amd64.tar.gz | tar -C /usr/local -xzf -

# Install Go-based recon tools
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
    go install github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install github.com/lc/gau/v2/cmd/gau@latest && \
    go install github.com/tomnomnom/waybackurls@latest && \
    go install github.com/hakluke/hakrawler@latest

WORKDIR /app

# Install Python deps (production only — no [dev] extras)
COPY pyproject.toml ./
RUN pip install --no-cache-dir .

# Copy source
COPY . .

# Create data directory
RUN mkdir -p /app/data/models /app/data/reports /app/data/logs

# Non-root user
RUN useradd -m -s /bin/bash bbhunter && chown -R bbhunter:bbhunter /app
USER bbhunter

EXPOSE 8443

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -sf http://127.0.0.1:8443/api/health || exit 1

ENTRYPOINT ["python", "-m", "bbhunter.cli"]
CMD ["dashboard", "--host", "0.0.0.0", "--port", "8443"]
