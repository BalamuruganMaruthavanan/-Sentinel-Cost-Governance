# AI-Driven Security Log Waste Reduction & DCR Transformation Engine
# Production-oriented Streamlit image (official Streamlit Docker patterns).
#
# Build:  docker build -t mca-sentinel-waste-engine .
# Run:    docker run --rm -p 8501:8501 mca-sentinel-waste-engine

FROM python:3.12-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    STREAMLIT_SERVER_PORT=8501 \
    STREAMLIT_SERVER_ADDRESS=0.0.0.0 \
    STREAMLIT_BROWSER_GATHER_USAGE_STATS=false

# curl is used by HEALTHCHECK; ca-certificates for HTTPS (SP / Azure APIs).
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies first (better layer caching).
COPY requirements.txt .
RUN pip3 install -r requirements.txt

# Application source + product docs + Streamlit theme
COPY app.py .
COPY BUILD_GUIDE.md .
COPY PRODUCT_CATALOG.md .
COPY .streamlit ./.streamlit

# Writable folder for governance trend history (Enhancement #7)
RUN mkdir -p /app/data \
    && useradd --create-home --shell /bin/bash appuser \
    && chown -R appuser:appuser /app
USER appuser

EXPOSE 8501

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl --fail http://localhost:8501/_stcore/health || exit 1

ENTRYPOINT ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0"]
