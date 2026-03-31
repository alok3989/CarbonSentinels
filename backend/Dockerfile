FROM python:3.11-slim

WORKDIR /app

# Core compilation bindings for scikit-learn & cryptography algorithms
RUN apt-get update && apt-get install -y \
    build-essential \
    libpq-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Strict dependency mapping
COPY requirements.txt .

# Pre-compile the isolated wheel configurations structurally to prevent memory bloat
RUN pip install --no-cache-dir --upgrade pip setuptools wheel
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install --no-cache-dir psycopg2-binary gunicorn

# Import architecture blocks
COPY . .

EXPOSE 8000

# Mount Gunicorn bound asynchronously with Uvicorn worker threads to sustain high-frequency WS queues
CMD ["gunicorn", "main:app", "--workers", "4", "--worker-class", "uvicorn.workers.UvicornWorker", "--bind", "0.0.0.0:8000"]
