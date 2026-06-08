FROM python:3.11-slim
WORKDIR /app

# Install minimal build deps
RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc libpq-dev curl \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY . /app

# Install Python dependencies (root requirements + dashboard requirements)
RUN pip install --no-cache-dir -r requirements.txt \
    && if [ -f dashboard/requirements.txt ]; then pip install --no-cache-dir -r dashboard/requirements.txt; fi

# Ensure start script is executable
COPY start.sh /app/start.sh
RUN chmod +x /app/start.sh

EXPOSE 8000

CMD ["/app/start.sh"]
