#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=== ELK Stack Setup ==="

# Check for Docker
if ! command -v docker &>/dev/null; then
    echo "Docker not found. Installing Docker..."

    # Install prerequisites
    sudo apt-get update
    sudo apt-get install -y ca-certificates curl gnupg

    # Add Docker GPG key
    sudo install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/debian/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    sudo chmod a+r /etc/apt/keyrings/docker.gpg

    # Add Docker repository
    echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian bookworm stable" \
        | sudo tee /etc/apt/sources.list.d/docker.list

    # Install Docker
    sudo apt-get update
    sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

    echo "Docker installed successfully."
else
    echo "Docker found: $(docker --version)"
fi

# Ensure current user is in the docker group
if ! groups | grep -q '\bdocker\b'; then
    echo "Adding $USER to the docker group..."
    sudo usermod -aG docker "$USER"
    echo "Group membership updated. Running the rest of the script with the docker group..."
    exec sg docker -c "bash '$SCRIPT_DIR/setup.sh' --skip-docker-check"
fi

# Create Logstash config directories
echo "Setting up Logstash configuration..."
mkdir -p "$SCRIPT_DIR/logstash/config"
mkdir -p "$SCRIPT_DIR/logstash/pipeline"

# Create Filebeat config directories
echo "Setting up Filebeat configuration..."
mkdir -p "$SCRIPT_DIR/filebeat/modules.d"

# Write logstash.yml if it doesn't exist
if [ ! -f "$SCRIPT_DIR/logstash/config/logstash.yml" ]; then
    cat > "$SCRIPT_DIR/logstash/config/logstash.yml" <<'EOF'
http.host: "0.0.0.0"
xpack.monitoring.elasticsearch.hosts: ["http://elasticsearch:9200"]
EOF
    echo "Created logstash.yml"
fi

# Write logstash.conf if it doesn't exist
if [ ! -f "$SCRIPT_DIR/logstash/pipeline/logstash.conf" ]; then
    cat > "$SCRIPT_DIR/logstash/pipeline/logstash.conf" <<'EOF'
input {
  tcp {
    port => 5000
    codec => json_lines
  }
  beats {
    port => 5044
  }
}

filter {
  if [message] {
    mutate {
      strip => ["message"]
    }
  }
}

output {
  elasticsearch {
    hosts => ["http://elasticsearch:9200"]
    index => "logstash-%{+YYYY.MM.dd}"
  }
  stdout {
    codec => rubydebug
  }
}
EOF
    echo "Created logstash.conf"
fi

# Check for AWS credentials in .env
if grep -q 'your-access-key-id-here\|your-secret-access-key-here' "$SCRIPT_DIR/.env"; then
    echo ""
    echo "WARNING: AWS credentials not configured in $SCRIPT_DIR/.env"
    echo "Edit .env and replace the placeholder values before Filebeat can poll CloudTrail logs."
    echo ""
fi

# Start the stack
echo "Starting ELK stack..."
cd "$SCRIPT_DIR"
docker compose up -d

# Wait for Elasticsearch to be healthy
echo "Waiting for Elasticsearch to be ready..."
until curl -sf http://localhost:9200/_cluster/health &>/dev/null; do
    sleep 5
done
echo "Elasticsearch is ready."

# Wait for Kibana
echo "Waiting for Kibana to be ready..."
until curl -sf http://localhost:5601/api/status &>/dev/null; do
    sleep 5
done
echo "Kibana is ready."

# Run Filebeat setup (index templates, ingest pipelines, Kibana dashboards)
echo "Running Filebeat setup (index templates, pipelines, dashboards)..."
docker compose run --rm filebeat filebeat setup --strict.perms=false \
    -E output.elasticsearch.hosts=["http://elasticsearch:9200"] \
    -E setup.kibana.host="http://kibana:5601"
echo "Filebeat setup complete."

echo ""
echo "=== ELK Stack is running ==="
echo "  Elasticsearch: http://localhost:9200"
echo "  Kibana:        http://localhost:5601"
echo "  Logstash TCP:  localhost:5000"
echo "  Logstash Beats: localhost:5044"
echo ""
echo "  Filebeat:  CloudTrail via S3 polling"
echo ""
echo "To stop:    docker compose -f $SCRIPT_DIR/docker-compose.yml down"
echo "To view logs: docker compose -f $SCRIPT_DIR/docker-compose.yml logs -f"
echo "Filebeat logs: docker compose -f $SCRIPT_DIR/docker-compose.yml logs -f filebeat"
