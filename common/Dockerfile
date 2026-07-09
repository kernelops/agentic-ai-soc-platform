FROM python:3.11-slim

WORKDIR /app

# Install common dependencies
COPY common/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy modules the worker imports
COPY common/ /app/common/
COPY correlation/ /app/correlation/
COPY enrichment/ /app/enrichment/

CMD ["python", "-m", "common.worker"]
