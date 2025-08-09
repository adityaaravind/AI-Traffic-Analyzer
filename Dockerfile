# syntax=docker/dockerfile:1
FROM python:3.11-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src

# Install tshark + setcap so non-root capture is possible
RUN apt-get update && apt-get install -y --no-install-recommends \
      tshark ca-certificates libcap2-bin \
    && setcap cap_net_raw,cap_net_admin+eip /usr/bin/dumpcap || true \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN addgroup --system app && adduser --system --ingroup app --home /home/app app


WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY src ./src
COPY templates ./templates
COPY README.md ./

# Make project writable by the non-root user
RUN chown -R app:app /app

USER app

# Default prints help; override in `docker run`
CMD ["python", "-m", "src.main", "--help"]
