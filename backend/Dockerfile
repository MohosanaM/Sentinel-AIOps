FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=5000

WORKDIR /app

# Dependencies first, so this layer is cached until requirements.txt changes.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Only what the API needs at runtime: no datasets, tests or .env files.
COPY schema.py url_analyzer.py sentinel_bridge.py ./
COPY sentinel_model.joblib replay_sample.csv.gz ./

RUN useradd --create-home appuser
USER appuser

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=40s \
  CMD python -c "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:' + os.environ.get('PORT', '5000') + '/api/health')"

# One worker: incidents and the blocklist are kept in memory.
CMD ["sh", "-c", "gunicorn -w 1 --threads 4 --timeout 60 -b 0.0.0.0:${PORT} sentinel_bridge:app"]
