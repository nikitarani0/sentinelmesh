FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Don't run as root inside the container.
RUN useradd --create-home --uid 10001 appuser
USER appuser

CMD exec uvicorn main:app --host 0.0.0.0 --port ${PORT:-8080}
