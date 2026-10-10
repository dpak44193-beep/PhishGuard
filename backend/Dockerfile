FROM python:3.11-slim

WORKDIR /app

# Install system deps for python-whois
RUN apt-get update && apt-get install -y --no-install-recommends \
    whois \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy monorepo modules the backend depends on
COPY backend/ backend/
COPY ml/ ml/
COPY cti/ cti/
COPY shared/ shared/

WORKDIR /app/backend
ENV PYTHONPATH=/app

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
