FROM python:3.12-slim

LABEL maintainer="Ali AlEnezi <site@hotmail.com>"
LABEL description="ICS/IoT/OT Hardening Framework — Industrial Security Toolkit"
LABEL version="2.0.0"

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    tcpdump \
    net-tools \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml .
COPY src/ src/
COPY scripts/ scripts/
COPY templates/ templates/
COPY requirements.txt .

RUN pip install --no-cache-dir -e ".[full]" 2>/dev/null || pip install --no-cache-dir -e .

RUN mkdir -p /app/reports /app/output /app/backups

EXPOSE 8080

ENTRYPOINT ["ics-harden"]
CMD ["--help"]
