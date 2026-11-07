# Base pinned by digest (python:3.12-slim)
FROM python:3.12-slim@sha256:4840d514c583a4d3d8cad3940e68dee6f0f6f3635c12fcd0a3d74c21a5b93a54
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir --require-hashes -r requirements.txt
COPY app/ app/
USER 10001
EXPOSE 8080
CMD ["gunicorn", "-b", "0.0.0.0:8080", "app.app:app"]
