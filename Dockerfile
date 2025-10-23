# Python slim image
FROM python:3.11-slim

# Set workdir
WORKDIR /app

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends     build-essential &&     rm -rf /var/lib/apt/lists/*

# Copy app
COPY . /app

# Install deps
RUN pip install --no-cache-dir -r requirements.txt

# Expose port
EXPOSE 10000

# Env
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    FLASK_ENV=production

# Start with gunicorn
# Bind to 0.0.0.0:10000 to match Render default for Docker
CMD ["gunicorn", "-w", "2", "-k", "gthread", "-b", "0.0.0.0:10000", "app:app"]
