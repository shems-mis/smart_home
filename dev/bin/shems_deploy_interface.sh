#!/bin/bash

# Check if running as root
if [ "$(id -u)" -eq 0 ]; then
    echo -e "This script should not be run as root. Please run as a regular user."
    exit 1
fi

# Configure paths
HTML_DIR="/app/smarthome/dev/templates"
SCRIPT_DIR="/app/smarthome/dev/bin"
DB_DIR="/app/smarthome/data"
LOG_DIR="/app/smarthome/data/logs"

# Create directories
mkdir -p "$HTML_DIR" "$SCRIPT_DIR" "$DB_DIR" "$LOG_DIR"

# Log file
LOG_FILE="$LOG_DIR/shems_deployment.log"
exec > >(tee -a "$LOG_FILE") 2>&1

echo -e "\e[31m🔥Starting SHEMS deployment at $(date) \e[0m"

# Check for existing processes and kill them
echo -e "`date` \e[36mℹ️ Checking for existing processes..."
pkill -f "shems_monitoring_server.py" || echo -e "No existing server process found"
pkill -f "shems_data_simulation.py" || echo -e "No existing simulation process found"

# Install required packages
echo -e "`date` \e[35m🛠️ Installing required packages... \e[0m"
sudo apt-get update > /dev/null

# Configure MariaDB
echo -e "`date` \e[35m🛠️ Configuring MariaDB... \e[0m"
mariadb --version

# Create Python virtual environment
echo -e "`date` \e[35m🛠️ Setting up Python environment... \e[0m"
python3 -m venv "$SCRIPT_DIR/venv" > /dev/null
source "$SCRIPT_DIR/venv/bin/activate" > /dev/null

# Install Python dependencies
echo -e "`date` \e[35m🛠️ Configuring Flask ... \e[0m"
flask --version

# Copy HTML templates
echo -e "`date` \e[35m🛠️ Deploying HTML templates... \e[0m"

# Copy Python scripts
echo -e  "`date` \e[35m🛠️ Deploying Python scripts... \e[0m" 

#Deploy Tailscale
echo -e  "`date` \e[35m🛠️ Configuring Tailscale... \e[0m"
tailscale version

# Deploy Grafana
echo -e "`date` \e[35m🛠️ Configuring Grafana... \e[0m"
grafana-server --version
echo -e "`date` \e[34m➡️ Deploying Grafana... \e[0m"
sh $SCRIPT_DIR/shems_deploy_grafana.sh  


# Start the monitoring server
echo -e " `date` \e[34m➡️ Starting monitoring server... \e[0m"
nohup "$SCRIPT_DIR/venv/bin/python" "$SCRIPT_DIR/shems_monitoring_server.py" >> "$LOG_DIR/shems_server.log" 2>&1 &

# Wait for server to start (max 30 seconds)
echo -e "Waiting for server to start..."
for i in {1..30}; do
    if curl -s "http://localhost:5000" > /dev/null; then
        echo -e " `date` \e[32m✔️ Server is running \e[0m"
        break
    fi
    sleep 1
done

if ! curl -s "http://localhost:5000" > /dev/null; then
    echo -e "`date` \e[31m❌ Server failed to start within 30 seconds \e[0m"
    exit 1
fi

# Get Raspberry Pi IP
PI_IP=$(hostname -I | awk '{print $1}')
if [ -z "$PI_IP" ]; then
    PI_IP="127.0.0.1"
fi

# Get Tailscale IP if available
TAILSCALE_IP=$(tailscale ip -4 2>/dev/null | head -n1 || echo -e "")

echo -e ""
echo -e "`date` \e[32m✔️ Deployment completed successfully!"
echo -e ""
echo -e -e " `date` \e[32m✔️ Access points: \e[0m"
echo -e -e " `date` \e[36mℹ️  - Web Interface (Local): http://$PI_IP:5000 \e[0m"
if [ -n "$TAILSCALE_IP" ]; then
    echo -e -e " `date` \e[36mℹ️ - Web Interface (Tailscale): http://$TAILSCALE_IP:5000"
fi
echo -e -e " `date` \e[36mℹ️ - Grafana (Local): http://$PI_IP:3000 \e[0m"
if [ -n "$TAILSCALE_IP" ]; then
    echo -e -e  " `date` \e[36mℹ️ - Grafana (Tailscale): http://$TAILSCALE_IP:3000 \e[0m"
fi
echo -e ""
echo -e -e " `date` \e[32m✔️ Log files are available in: $LOG_DIR \e[0m"
echo -e -e " `date` \e[32m✔️ Deployment completed !!! Thank you !\e[0m"

echo -e -e "\e[32m✔️  Data processed successfully.\e[0m"
