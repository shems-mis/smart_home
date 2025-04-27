#!/bin/bash

# Check if running as root
if [ "$(id -u)" -eq 0 ]; then
    echo "This script should not be run as root. Please run as a regular user."
    exit 1
fi

# Configure paths
LOG_DIR="/app/smarthome/data/logs"
mkdir -p "$LOG_DIR"

# Log file
LOG_FILE="$LOG_DIR/shems_grafana_deploy.log"
#exec > >(tee -a "$LOG_FILE") 2>&1

echo "Starting Grafana deployment at $(date)"


# Wait for Grafana to start (max 30 seconds)
echo "Waiting for Grafana to start..."
for i in {1..30}; do
    if systemctl is-active --quiet grafana-server; then
        echo "Grafana is running"
        break
    fi
    sleep 1
done

if ! systemctl is-active --quiet grafana-server; then
    echo "Grafana failed to start within 30 seconds"
    exit 1
fi

# Configure Grafana data source (MySQL)
echo "Configuring Grafana data source..."

# Get MySQL credentials from environment
DB_USER="${DB_USER}"
DB_PASS="${DB_PASS}"
DB_NAME="${DB_NAME}"
GRAFANA_USER="${GRAFANA_USER}"
GRAFANA_PASS="${GRAFANA_PASS}"

# Get Raspberry Pi IP
PI_IP=$(hostname -I | awk '{print $1}')

# Create data source configuration
DATASOURCE_JSON=$(cat <<EOF
{
  "name": "SHEMS-MySQLDB",
  "type": "mysql",
  "url": "$PI_IP:3306",
  "database": "$DB_NAME",
  "user": "$DB_USER",
  "password": "$DB_PASS",
  "access": "proxy",
  "isDefault": true,
  "jsonData": {
    "maxOpenConns": 10,
    "maxIdleConns": 5,
    "connMaxLifetime": 14400
  }
}
EOF
)

# Configure data source using Grafana API
for i in {1..10}; do
    RESPONSE=$(curl -s -X POST "http://localhost:3000/api/datasources" \
        -H "Content-Type: application/json" \
        -d "$DATASOURCE_JSON" \
        -u "${GRAFANA_USER}:${GRAFANA_PASS}")

    if echo "$RESPONSE" | grep -q "Datasource added"; then
        echo "Data source configured successfully"
        break
    elif echo "$RESPONSE" | grep -q "already exists"; then
        echo "Data source already exists"
        break
    else
        echo "Attempt $i: Failed to configure data source, retrying..."
        sleep 3
    fi
done

# Import dashboards
echo "Importing Grafana dashboards..."

# Dashboard files
DASHBOARD_DIR="/app/smarthome/grafana/grafana_dashboards"
mkdir -p "$DASHBOARD_DIR"

# Import dashboards using Grafana API
for dashboard in "$DASHBOARD_DIR"/*.json; do
    dashboard_name=$(basename "$dashboard" .json)
    echo "Importing dashboard: $dashboard_name"

    for i in {1..5}; do
        RESPONSE=$(curl -s -X POST "http://localhost:3000/api/dashboards/db" \
            -H "Content-Type: application/json" \
            -d "$(jq -n --argfile dash $dashboard '{dashboard: $dash, overwrite: true}')" \
            -u "${GRAFANA_USER}:${GRAFANA_PASS}")

        if echo "$RESPONSE" | grep -q '"status":"success"'; then
            echo "Dashboard $dashboard_name imported successfully"
            break
        else
            echo "Attempt $i: Failed to import dashboard $dashboard_name, retrying..."
            sleep 3
        fi
    done
done

echo "Grafana deployment completed at $(date)"



