FROM python:3.11-slim

WORKDIR /app

# Install common dependencies
COPY common/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Pre-bake the FastEmbed model into the image so RAG works offline at runtime
# (no model download on first query/ingest). Must match rag_embedding_model /
# rag_embedding_cache_dir in common/config.py.
RUN python -c "from fastembed import TextEmbedding; TextEmbedding(model_name='BAAI/bge-small-en-v1.5', cache_dir='/app/models')"

# Copy modules the worker imports
COPY common/ /app/common/
COPY correlation/ /app/correlation/
COPY enrichment/ /app/enrichment/
COPY rag/ /app/rag/
COPY agents/ /app/agents/

CMD ["python", "-m", "common.worker"]
