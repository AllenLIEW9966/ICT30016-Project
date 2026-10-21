FROM python:3.12-slim

# Node for the O-01 @babel/parser JS sidecar
RUN apt-get update && apt-get install -y --no-install-recommends nodejs npm \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY js-ast/package.json js-ast/package-lock.json* ./js-ast/
RUN cd js-ast && npm install --omit=dev --no-audit --no-fund
COPY . .

EXPOSE 8000
# C7: bind loopback only in container; override with -p to map. Use reverse proxy for remote access.
CMD ["uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "8000"]
