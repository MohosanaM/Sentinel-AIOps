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

# Copy everything in backend/ (scripts, data, any models that exist)
COPY backend/ ./

# Train the model during build if sentinel_model.joblib wasn't in Git
RUN if [ ! -f sentinel_model.joblib ] && [ -f train.py ]; then python train.py; fi
RUN if [ -f train_url.py ]; then python train_url.py || true; fi

# Copy built Flutter web files into ./static
COPY --from=flutter-build /app/frontend/build/web ./static

RUN useradd --create-home appuser
USER appuser

EXPOSE 5000

CMD ["sh", "-c", "gunicorn -w 1 --threads 4 --timeout 60 -b 0.0.0.0:${PORT} sentinel_bridge:app"]
