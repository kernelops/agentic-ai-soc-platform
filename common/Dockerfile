FROM python:3.11-slim

WORKDIR /app

# Install common dependencies
COPY common/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy common module
COPY common/ /app/common/

CMD ["python", "-m", "common.worker"]
