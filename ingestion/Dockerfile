FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY ingestion/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy common module (shared models, config, database)
COPY common/ /app/common/

# Copy ingestion service
COPY ingestion/ /app/ingestion/

EXPOSE 8000

CMD ["uvicorn", "ingestion.main:app", "--host", "0.0.0.0", "--port", "8000", "--log-level", "info"]
