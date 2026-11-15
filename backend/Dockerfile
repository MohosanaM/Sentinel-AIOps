# Stage 1: Build Flutter web inside Docker
FROM ghcr.io/cirruslabs/flutter:stable AS flutter-build
WORKDIR /app/frontend
COPY frontend/pubspec.* ./
RUN flutter pub get
COPY frontend/ .
RUN flutter build web --release

# Stage 2: Run Python backend + serve Flutter
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=5000

WORKDIR /app

COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/schema.py backend/url_analyzer.py backend/sentinel_bridge.py ./
COPY backend/sentinel_model.joblib backend/replay_sample.csv.gz ./

COPY --from=flutter-build /app/frontend/build/web ./static

RUN useradd --create-home appuser
USER appuser

EXPOSE 5000

CMD ["sh", "-c", "gunicorn -w 1 --threads 4 --timeout 60 -b 0.0.0.0:${PORT} sentinel_bridge:app"]
