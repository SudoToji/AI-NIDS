# AI-NIDS ELK Stack Setup

This guide explains how to set up the ELK Stack (Elasticsearch, Logstash, Kibana) for the AI-NIDS project.

## Prerequisites

- Docker Desktop installed and running
- At least 4GB RAM available for ELK containers
- AI-NIDS project already set up

## Quick Start

### 1. Start the ELK Stack

```bash
cd C:\Users\Mazen\Desktop\project
docker-compose -f elk\docker-compose.elk.yml up -d
```

Wait for all containers to be healthy (may take 2-3 minutes on first start).

### 2. Verify ELK is Running

Check container status:
```bash
docker ps
```

You should see three containers running:
- `ainids-elasticsearch`
- `ainids-logstash`
- `ainids-kibana`

### 3. Access Kibana

Open your browser and navigate to:
```
http://localhost:5601
```

### 4. Configure API Keys (Optional)

Edit the `.env` file to add your API keys:

```bash
# Copy the example file
copy .env.example .env

# Edit with your API keys
notepad .env
```

Add your keys:
```
VIRUSTOTAL_API_KEY=your_virustotal_key
ABUSEIPDB_API_KEY=your_abuseipdb_key
ELK_ENABLED=true
```

### 5. Enable ELK Forwarding in Dashboard

In the AI-NIDS dashboard, go to Settings and enable "Forward to ELK".

Or set the environment variable:
```bash
set ELK_ENABLED=true
python -m src.api.server
```

## Directory Structure

```
elk/
├── docker-compose.elk.yml     # Docker Compose for ELK Stack
├── logstash/
│   ├── pipeline/
│   │   └── nids.conf          # Logstash pipeline config
│   └── config/
│       └── logstash.yml       # Logstash settings
└── kibana/
    └── kibana.yml             # Kibana settings
```

## Services

### Elasticsearch (Port 9200)
- **Purpose**: Document storage and search
- **Web UI**: http://localhost:9200
- **Health**: http://localhost:9200/_cluster/health

### Logstash (Port 5044)
- **Purpose**: Process alerts from AI-NIDS
- **Input**: TCP JSON on port 5044
- **Output**: Elasticsearch with daily indices

### Kibana (Port 5601)
- **Purpose**: Visualization and dashboards
- **URL**: http://localhost:5601
- **Default**: No authentication required (local dev)

## Creating Kibana Index Pattern

After ELK starts:

1. Open Kibana at http://localhost:5601
2. Go to **Stack Management** → **Index Patterns**
3. Click **Create index pattern**
4. Enter pattern: `ainids-alerts-*`
5. Select time field: `@timestamp`
6. Click **Create index pattern**

## Sample Kibana Dashboards

### 1. SOC Overview Dashboard
Create visualizations:
- **Metric**: Total alerts count
- **Pie chart**: Attack type distribution
- **Data table**: Top attacking IPs
- **Line chart**: Alerts over time

### 2. Threat Investigation Dashboard
Create visualizations:
- **Map**: Geographic distribution of attacks
- **Heatmap**: Attack intensity by hour
- **Tag cloud**: Most common attack types
- **Table**: Recent high-severity alerts

### 3. Model Performance Dashboard
Create visualizations:
- **Bar chart**: Detection accuracy by model
- **Pie chart**: Model agreement/disagreement
- **Timeline**: Model predictions over time

## Troubleshooting

### Containers Won't Start

Check Docker resources:
```bash
docker stats
```

Increase memory in Docker Desktop settings if needed (4GB recommended).

### Elasticsearch Out of Memory

Edit `docker-compose.elk.yml`:
```yaml
environment:
  - "ES_JAVA_OPTS=-Xms512m -Xmx512m"
```

### Kibana Can't Connect to Elasticsearch

Wait for Elasticsearch to be fully ready, then restart Kibana:
```bash
docker-compose -f elk\docker-compose.elk.yml restart kibana
```

### Logstash Not Receiving Data

Check Logstash logs:
```bash
docker logs ainids-logstash
```

Verify ELK forwarding is enabled in AI-NIDS.

## Stopping the ELK Stack

```bash
docker-compose -f elk\docker-compose.elk.yml down
```

To also remove data volumes:
```bash
docker-compose -f elk\docker-compose.elk.yml down -v
```

## Data Retention

By default, Elasticsearch indices are created daily:
```
ainids-alerts-2026.03.20
ainids-alerts-2026.03.21
...
```

To manage retention, either:
- Delete old indices manually in Kibana
- Use Elasticsearch Curator (external tool)
- Set up ILM (Index Lifecycle Management) in Logstash config

## Security Notes

For production deployment:
1. Enable X-Pack security
2. Set up authentication
3. Use HTTPS for all connections
4. Restrict network access
5. Rotate API keys regularly

## Resources

- [Elasticsearch Documentation](https://www.elastic.co/guide/en/elasticsearch/reference/current/index.html)
- [Logstash Documentation](https://www.elastic.co/guide/en/logstash/current/index.html)
- [Kibana Documentation](https://www.elastic.co/guide/en/kibana/current/index.html)
