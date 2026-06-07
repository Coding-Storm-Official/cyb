# 🚀 Production Deployment Guide

## Overview

This guide walks you through deploying the AI SOC Platform to production environments.

---

## Option A: Standalone Server Deployment

### Use Case
Single security team, modest event volume (<10K events/min), one location.

### Step 1: Prepare Server

```bash
# Requirements: Python 3.8+, 4GB+ RAM, 20GB+ disk

# Update system
apt update && apt upgrade -y  # Ubuntu/Debian
yum update -y                  # RHEL/CentOS

# Install Python
apt install python3 python3-pip python3-venv  # Ubuntu/Debian
yum install python3 python3-pip                # RHEL/CentOS
```

### Step 2: Create Application Directory

```bash
mkdir -p /opt/xdr-platform
cd /opt/xdr-platform

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Copy application files
cp -r cyb-backend/* .
pip install -r requirements.txt
```

### Step 3: Configuration

Create `/opt/xdr-platform/.env`:

```bash
# Security
XDR_API_KEY=your-very-long-random-secret-key-here
XDR_SECRET=another-long-random-secret-key

# Server
HOST=0.0.0.0
PORT=8001
WORKERS=4

# Splunk
SPLUNK_HOST=splunk.company.com
SPLUNK_PORT=8089
SPLUNK_TOKEN=your-splunk-api-token
SPLUNK_USERNAME=admin
SPLUNK_PASSWORD=splunk-password

# Optional: Qwen AI
QWEN_HOST=http://localhost:11434
QWEN_MODEL=qwen2.5

# Optional: Webhooks
WEBHOOK_URL=https://your-webhook-receiver.com/alerts
WEBHOOK_TOKEN=webhook-auth-token

# Optional: Redis (for caching)
REDIS_HOST=127.0.0.1
REDIS_PORT=6379
REDIS_PASS=redis-password

# Optional: Kafka (for distributed queue)
KAFKA=kafka-broker-1:9092,kafka-broker-2:9092
```

### Step 4: Create Systemd Service

Create `/etc/systemd/system/xdr-platform.service`:

```ini
[Unit]
Description=AI SOC XDR Platform
After=network.target

[Service]
Type=notify
User=xdr
WorkingDirectory=/opt/xdr-platform
Environment="PATH=/opt/xdr-platform/venv/bin"
Environment="LD_LIBRARY_PATH=/opt/xdr-platform/venv/lib"
EnvironmentFile=/opt/xdr-platform/.env

ExecStart=/opt/xdr-platform/venv/bin/python main.py
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

### Step 5: Install & Start Service

```bash
# Create xdr user
useradd -r -s /bin/bash xdr
chown -R xdr:xdr /opt/xdr-platform

# Enable and start service
systemctl daemon-reload
systemctl enable xdr-platform
systemctl start xdr-platform

# Check status
systemctl status xdr-platform
journalctl -u xdr-platform -f
```

### Step 6: Set Up Reverse Proxy (Nginx)

Create `/etc/nginx/sites-available/xdr-platform`:

```nginx
upstream xdr_backend {
    server 127.0.0.1:8001;
}

server {
    listen 443 ssl http2;
    server_name xdr.company.com;

    ssl_certificate /etc/ssl/certs/xdr.crt;
    ssl_certificate_key /etc/ssl/private/xdr.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=xdr:10m rate=100r/s;
    limit_req zone=xdr burst=200 nodelay;

    location / {
        proxy_pass http://xdr_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Timeouts for long-running analysis
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }

    # Logging
    access_log /var/log/nginx/xdr-access.log combined;
    error_log /var/log/nginx/xdr-error.log;
}
```

Enable and restart:
```bash
ln -s /etc/nginx/sites-available/xdr-platform /etc/nginx/sites-enabled/
nginx -t
systemctl restart nginx
```

---

## Option B: Docker Container Deployment

### Use Case
Easy scaling, testing, cloud deployments (AWS, Azure, GCP).

### Step 1: Create Dockerfile

Create `Dockerfile`:

```dockerfile
FROM python:3.10-slim

WORKDIR /app

# Install dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Create non-root user
RUN useradd -m -u 1000 xdr && chown -R xdr:xdr /app
USER xdr

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8001/health')"

# Start application
CMD ["python", "main.py"]
```

### Step 2: Create Docker Compose

Create `docker-compose.yml`:

```yaml
version: '3.8'

services:
  xdr-platform:
    build: .
    ports:
      - "8001:8001"
    environment:
      HOST: 0.0.0.0
      PORT: 8001
      XDR_API_KEY: ${XDR_API_KEY}
      SPLUNK_HOST: ${SPLUNK_HOST}
      SPLUNK_TOKEN: ${SPLUNK_TOKEN}
    volumes:
      - xdr-db:/app/data
      - ./iocs.json:/app/iocs.json
    restart: unless-stopped
    networks:
      - xdr-network

  # Optional: Nginx reverse proxy
  nginx:
    image: nginx:latest
    ports:
      - "443:443"
      - "80:80"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./certs:/etc/nginx/certs:ro
    depends_on:
      - xdr-platform
    networks:
      - xdr-network

  # Optional: Redis for caching
  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis-data:/data
    networks:
      - xdr-network

  # Optional: PostgreSQL for persistent storage
  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: xdr
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    volumes:
      - postgres-data:/var/lib/postgresql/data
    networks:
      - xdr-network

volumes:
  xdr-db:
  redis-data:
  postgres-data:

networks:
  xdr-network:
    driver: bridge
```

### Step 3: Deploy

```bash
# Create .env file with secrets
echo "XDR_API_KEY=your-secret-key" > .env
echo "SPLUNK_HOST=splunk.company.com" >> .env
# ... add other variables

# Build and start
docker-compose up -d

# Check logs
docker-compose logs -f xdr-platform

# Verify health
curl http://localhost:8001/health
```

---

## Option C: Kubernetes Deployment (Enterprise)

### Step 1: Create Kubernetes Manifests

Create `k8s-deployment.yaml`:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: xdr-platform
  labels:
    app: xdr-platform
spec:
  replicas: 3
  selector:
    matchLabels:
      app: xdr-platform
  template:
    metadata:
      labels:
        app: xdr-platform
    spec:
      containers:
      - name: xdr-platform
        image: xdr-platform:latest
        ports:
        - containerPort: 8001
        env:
        - name: XDR_API_KEY
          valueFrom:
            secretKeyRef:
              name: xdr-secrets
              key: api-key
        - name: SPLUNK_HOST
          valueFrom:
            configMapKeyRef:
              name: xdr-config
              key: splunk-host
        resources:
          requests:
            memory: "2Gi"
            cpu: "1"
          limits:
            memory: "4Gi"
            cpu: "2"
        livenessProbe:
          httpGet:
            path: /health
            port: 8001
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 8001
          initialDelaySeconds: 10
          periodSeconds: 5
        volumeMounts:
        - name: xdr-storage
          mountPath: /app/data
      volumes:
      - name: xdr-storage
        persistentVolumeClaim:
          claimName: xdr-pvc

---
apiVersion: v1
kind: Service
metadata:
  name: xdr-platform-service
spec:
  selector:
    app: xdr-platform
  ports:
  - protocol: TCP
    port: 443
    targetPort: 8001
  type: LoadBalancer
```

### Step 2: Deploy to K8s

```bash
# Create secrets
kubectl create secret generic xdr-secrets \
  --from-literal=api-key=your-secret-key

# Create ConfigMap
kubectl create configmap xdr-config \
  --from-literal=splunk-host=splunk.company.com

# Deploy
kubectl apply -f k8s-deployment.yaml

# Check status
kubectl get pods
kubectl get svc xdr-platform-service
```

---

## Monitoring & Maintenance

### Health Checks

```bash
# Every 5 minutes
curl -s http://xdr-platform:8001/health | jq .

# Alert if queue is backing up
curl -s http://xdr-platform:8001/health | jq '.queue_depth'
```

### Log Management

```bash
# View logs
journalctl -u xdr-platform -f

# Or with Docker
docker-compose logs -f xdr-platform

# Or with Kubernetes
kubectl logs -f deployment/xdr-platform
```

### Performance Monitoring

```bash
# Check Prometheus metrics
curl http://xdr-platform:8001/metrics

# Monitor in your observability tool (Datadog, Splunk, New Relic, etc.)
```

### Backup Strategy

```bash
# Backup SQLite database
tar czf xdr-backup-$(date +%Y%m%d).tar.gz /app/data/xdr.db /app/iocs.json

# Copy to S3 or backup location
aws s3 cp xdr-backup-*.tar.gz s3://backups/xdr/
```

---

## Security Hardening

### 1. API Key Rotation

```bash
# Generate new key monthly
openssl rand -base64 32

# Update in .env
# Restart service
systemctl restart xdr-platform
```

### 2. Network Security

```bash
# Only allow internal access to port 8001
ufw allow from 10.0.0.0/8 to any port 8001

# Use TLS/SSL for all connections
# Certificate from Let's Encrypt or your CA
```

### 3. Database Security

```bash
# If using PostgreSQL, use strong passwords
# Change default SQLite location to restricted directory
chmod 600 /app/data/xdr.db
chown xdr:xdr /app/data/xdr.db
```

### 4. Secrets Management

Instead of `.env` files, use:
- **AWS Secrets Manager**
- **HashiCorp Vault**
- **Azure Key Vault**
- **Kubernetes Secrets**

---

## Scaling for Production

### Vertical Scaling (More Resources)

```bash
# Increase workers (in .env)
XDR_WORKERS=16  # Instead of 4

# Increase queue size (in ml.py)
self.queue = queue.Queue(maxsize=500000)  # Instead of 200k
```

### Horizontal Scaling (Multiple Servers)

1. **Load Balancer** (HAProxy or AWS ALB)
2. **Shared Database** (PostgreSQL instead of SQLite)
3. **Shared Cache** (Redis)
4. **Distributed Queue** (Kafka)

```nginx
upstream xdr_cluster {
    server xdr-1.company.com:8001 weight=5;
    server xdr-2.company.com:8001 weight=5;
    server xdr-3.company.com:8001 weight=5;
}
```

---

## Troubleshooting Deployment

### Service won't start

```bash
# Check logs
journalctl -u xdr-platform -n 50

# Check Python errors
python /opt/xdr-platform/main.py

# Check permissions
ls -la /opt/xdr-platform
```

### Can't connect to Splunk

```bash
# Test network
telnet splunk.company.com 8089

# Test DNS
nslookup splunk.company.com

# Check credentials
echo $SPLUNK_TOKEN
```

### High memory usage

```bash
# Check queue depth
curl http://localhost:8001/health | jq .queue_depth

# Reduce workers if overloaded
XDR_WORKERS=2
```

---

## Runbook Template

### Incident Response

```
If system is down:
1. SSH to server
2. systemctl status xdr-platform
3. Check logs: journalctl -u xdr-platform -f
4. Restart: systemctl restart xdr-platform
5. Verify: curl http://localhost:8001/health

If queue is backing up:
1. Check alerts: curl http://localhost:8001/alerts
2. Increase workers: XDR_WORKERS=8
3. Monitor: watch -n 5 'curl -s http://localhost:8001/health | jq'

If false positives increase:
1. Adjust threshold: Engine.THRESHOLD = 70 (was 65)
2. Review alerts: /alerts endpoint
3. Mark false positives to retrain model
4. Restart service
```

---

## Post-Deployment Checklist

- [ ] Service starts automatically on reboot
- [ ] Health check passes
- [ ] Can receive events via /ingest
- [ ] Can retrieve alerts via /alerts
- [ ] Splunk connection working
- [ ] Logs are being collected
- [ ] Monitoring/alerting is active
- [ ] Backups are scheduled
- [ ] Team is trained
- [ ] Runbooks documented

---

**For questions, see README.md or contact your system administrator**
