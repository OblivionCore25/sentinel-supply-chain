# Sentinel — Real-Time Software Supply Chain Risk Monitor

A real-time event-driven platform that continuously monitors software dependencies for security risks, vulnerability disclosures, and suspicious changes — surfacing actionable insights through a live dashboard.

Built with **Java 21**, **Spring Boot 3**, **Apache Kafka**, and **React/TypeScript**.

---

## Why This Exists

Modern software projects depend on hundreds of transitive dependencies, and a single compromised package deep in the tree can silently propagate risk upward. Most existing tools perform point-in-time scans, but supply chain attacks and vulnerability disclosures happen continuously. Sentinel treats dependency monitoring as a **streaming problem** — ingesting events in real time, scoring risk across the full dependency graph, and notifying teams the moment their exposure changes.

The risk scoring methodology draws from research on cross-level risk propagation in software supply chains, analyzing how vulnerabilities in deeply nested transitive dependencies amplify risk at the application level — a pattern traditional scanners frequently miss.

---

## How Sentinel Differs from Existing Tools

| Capability | Dependency-Track | Snyk | OSV-Scanner | Trivy/Grype | **Sentinel** |
| --- | --- | --- | --- | --- | --- |
| **Detection model** | Batch SBOM import | CI/CD scan on push | CLI point-in-time scan | CLI scan | **Real-time event streaming via Kafka** |
| **Transitive risk scoring** | Binary (affected/not) | Reachability analysis (commercial) | Binary | Binary | **Multi-factor propagation scoring (depth, fan-out, freshness)** |
| **Scoring methodology** | CVSS only | CVSS + reachability | CVSS only | CVSS only | **Research-backed model quantifying cross-level risk amplification** |
| **Dashboard updates** | Refresh on page load | Web UI (polling) | None (CLI) | None (CLI) | **Real-time WebSocket push** |
| **Architecture** | Monolithic Java app | Commercial SaaS | Standalone CLI | Standalone CLI | **Event-driven microservices (Spring Boot + Kafka)** |
| **Hidden amplifier detection** | No | No | No | No | **Yes — identifies vulnerabilities amplified by multiple transitive paths** |
| **Open source** | Yes | No (freemium) | Yes | Yes | **Yes** |

### The Key Insight

Traditional tools answer: *"Does this project have a known vulnerability?"* — a binary yes/no.

Sentinel answers: *"How much risk does this vulnerability actually pose to this project, given the dependency graph topology?"* A moderate-severity CVE (CVSS 5.0) reachable through 8 transitive paths is objectively more dangerous than a high-severity CVE (CVSS 7.0) behind a single direct dependency — but no existing tool quantifies this. Sentinel does, using a scoring model grounded in ongoing research on supply chain risk propagation.

---

## Architecture Overview

Sentinel follows an event-driven microservices architecture with Kafka as the central nervous system. Each service has a single responsibility and communicates exclusively through Kafka topics.

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   External       │     │   External       │     │   GitHub         │
│   CVE Feeds      │     │   Package        │     │   Advisory       │
│   (NVD, OSV)     │     │   Registries     │     │   Webhooks       │
└────────┬────────┘     └────────┬────────┘     └────────┬────────┘
         │                       │                       │
         └───────────┬───────────┴───────────────────────┘
                     │
                     ▼
        ┌────────────────────────┐
        │   Ingestion Service    │    (Spring Boot)
        │   - Webhook receivers  │
        │   - Feed pollers       │
        │   - Event normalization│
        └────────────┬───────────┘
                     │
          publishes to Kafka
                     │
         ┌───────────┼───────────────────┐
         ▼           ▼                   ▼
   ┌───────────┐ ┌───────────┐   ┌────────────┐
   │ topic:    │ │ topic:    │   │ topic:     │
   │ vuln.     │ │ dependency│   │ package.   │
   │ disclosed │ │ .updated  │   │ released   │
   └─────┬─────┘ └─────┬─────┘   └──────┬─────┘
         │             │                │
         └──────┬──────┴────────────────┘
                │
                ▼
   ┌────────────────────────┐
   │   Analysis Service     │    (Spring Boot)
   │   - Dependency resolver│
   │   - Graph builder      │
   │   - Risk scorer        │
   │   - Impact propagation │
   └────────────┬───────────┘
                │
     publishes to Kafka
                │
         ┌──────┴──────┐
         ▼             ▼
   ┌───────────┐ ┌───────────┐
   │ topic:    │ │ topic:    │
   │ risk.     │ │ risk.     │
   │ scores    │ │ alerts    │
   └─────┬─────┘ └─────┬─────┘
         │             │
         └──────┬──────┘
                │
                ▼
   ┌────────────────────────┐
   │  Notification Service  │    (Spring Boot)
   │  - WebSocket push      │
   │  - Alert aggregation   │
   │  - Threshold filtering │
   └────────────┬───────────┘
                │
          WebSocket
                │
                ▼
   ┌────────────────────────┐
   │   React Dashboard      │    (React + TypeScript)
   │   - Live risk overview │
   │   - Dependency graph   │
   │   - Event timeline     │
   │   - Project drill-down │
   └────────────────────────┘
```

---

## Tech Stack

| Layer              | Technology                                                       |
| ------------------ | ---------------------------------------------------------------- |
| **Backend**        | Java 21, Spring Boot 3.3, Spring WebFlux (WebSocket)             |
| **Messaging**      | Apache Kafka 3.7 (KRaft mode, no ZooKeeper)                     |
| **Frontend**       | React 18, TypeScript, D3.js (graph visualization), TailwindCSS   |
| **Database**       | PostgreSQL 16 (project metadata, dependency snapshots)           |
| **Cache**          | Redis (recent risk scores, dashboard state)                      |
| **Containerization** | Docker, Docker Compose                                         |
| **Build**          | Maven (backend), Vite (frontend)                                 |
| **Testing**        | JUnit 5, Mockito, Testcontainers (Kafka + PostgreSQL), React Testing Library |

---

## Kafka Topology

### Topics

| Topic                  | Key              | Value Schema                     | Partitions | Producer           | Consumer           |
| ---------------------- | ---------------- | -------------------------------- | ---------- | ------------------ | ------------------ |
| `vuln.disclosed`       | CVE ID           | `VulnerabilityEvent`             | 6          | Ingestion Service  | Analysis Service   |
| `dependency.updated`   | Package name     | `DependencyUpdateEvent`          | 6          | Ingestion Service  | Analysis Service   |
| `package.released`     | Package name     | `PackageReleaseEvent`            | 6          | Ingestion Service  | Analysis Service   |
| `risk.scores`          | Project ID       | `RiskScoreEvent`                 | 3          | Analysis Service   | Notification Service |
| `risk.alerts`          | Project ID       | `AlertEvent`                     | 3          | Analysis Service   | Notification Service |
| `risk.scores.dlq`      | Original key     | `FailedEvent`                    | 1          | Analysis Service   | — (manual review)  |

### Consumer Groups

| Group                        | Service              | Topics Consumed                                       |
| ---------------------------- | -------------------- | ----------------------------------------------------- |
| `analysis-vuln-group`        | Analysis Service     | `vuln.disclosed`                                      |
| `analysis-dependency-group`  | Analysis Service     | `dependency.updated`, `package.released`               |
| `notification-group`         | Notification Service | `risk.scores`, `risk.alerts`                           |

### Key Design Decisions

- **Partitioning by package name** on ingestion topics ensures all events for the same package are processed in order by the same consumer instance.
- **Partitioning by project ID** on risk topics ensures all scores and alerts for a given project are delivered to the same notification consumer, preventing out-of-order dashboard updates.
- **Dead letter topic** (`risk.scores.dlq`) captures events that fail analysis (e.g., unresolvable dependency trees) for manual investigation.
- **KRaft mode** (no ZooKeeper) simplifies the infrastructure and reflects the current Kafka production recommendation.

---

## Microservices Detail

### 1. Ingestion Service (`sentinel-ingestion`)

Receives external events and normalizes them into a common schema before publishing to Kafka.

**Responsibilities:**
- Expose REST endpoints for webhook callbacks (GitHub Advisory, npm registry, Maven Central)
- Poll external feeds on a schedule (NVD CVE feed, OSV database)
- Normalize heterogeneous event formats into internal event schemas
- Publish normalized events to the appropriate Kafka topics
- Idempotency: deduplicate events by source ID to prevent reprocessing

**Key Classes:**
```
sentinel-ingestion/
├── src/main/java/com/sentinel/ingestion/
│   ├── IngestApplication.java
│   ├── config/
│   │   └── KafkaProducerConfig.java
│   ├── controller/
│   │   ├── GitHubWebhookController.java        # POST /webhooks/github
│   │   ├── NpmWebhookController.java           # POST /webhooks/npm
│   │   └── ManualIngestController.java          # POST /api/ingest (for testing)
│   ├── poller/
│   │   ├── NvdFeedPoller.java                   # Scheduled CVE feed polling
│   │   └── OsvFeedPoller.java                   # OSV database polling
│   ├── model/
│   │   ├── VulnerabilityEvent.java
│   │   ├── DependencyUpdateEvent.java
│   │   └── PackageReleaseEvent.java
│   ├── normalizer/
│   │   ├── GitHubAdvisoryNormalizer.java
│   │   ├── NvdNormalizer.java
│   │   └── OsvNormalizer.java
│   ├── publisher/
│   │   └── EventPublisher.java                  # Generic Kafka producer wrapper
│   └── dedup/
│       └── EventDeduplicator.java               # Redis-backed idempotency check
```

**Kafka Producer Configuration:**
- Serialization: JSON (Jackson) with schema embedded in headers
- Acks: `all` (maximum durability for security-critical events)
- Retries: 3 with exponential backoff
- Idempotent producer enabled

---

### 2. Analysis Service (`sentinel-analysis`)

The core intelligence layer. Consumes raw events, resolves dependency graphs, computes risk scores, and propagates impact analysis across the transitive dependency tree.

**Responsibilities:**
- Consume events from all three ingestion topics
- Resolve the full transitive dependency tree for monitored projects
- Build an in-memory dependency graph (directed acyclic graph)
- Compute risk scores using a multi-factor model:
  - **Direct exposure**: Does the project directly depend on the affected package?
  - **Transitive depth**: How many hops away is the vulnerability?
  - **Dependency fan-out**: How many paths lead to the affected package?
  - **CVSS severity**: Base score from the vulnerability disclosure
  - **Freshness decay**: How recently was the vulnerability disclosed?
- Propagate risk scores upward through the graph to all affected projects
- Publish scored events to `risk.scores` and high-severity events to `risk.alerts`
- Route failed events to the dead letter topic

**Key Classes:**
```
sentinel-analysis/
├── src/main/java/com/sentinel/analysis/
│   ├── AnalysisApplication.java
│   ├── config/
│   │   ├── KafkaConsumerConfig.java
│   │   └── KafkaProducerConfig.java
│   ├── consumer/
│   │   ├── VulnerabilityConsumer.java           # Listens to vuln.disclosed
│   │   ├── DependencyUpdateConsumer.java        # Listens to dependency.updated
│   │   └── PackageReleaseConsumer.java          # Listens to package.released
│   ├── graph/
│   │   ├── DependencyGraph.java                 # DAG representation
│   │   ├── DependencyNode.java                  # Node with metadata
│   │   └── GraphBuilder.java                    # Builds graph from dependency trees
│   ├── resolver/
│   │   ├── DependencyResolver.java              # Interface
│   │   ├── MavenDependencyResolver.java         # Resolves Maven dependency trees
│   │   └── NpmDependencyResolver.java           # Resolves npm dependency trees
│   ├── scoring/
│   │   ├── RiskScorer.java                      # Orchestrates scoring pipeline
│   │   ├── TransitiveDepthFactor.java           # Depth-based decay function
│   │   ├── FanOutFactor.java                    # Multiple-path amplification
│   │   ├── CvssSeverityFactor.java              # CVSS base score weight
│   │   └── FreshnessDecayFactor.java            # Time-based relevance decay
│   ├── propagation/
│   │   └── RiskPropagator.java                  # Walks graph upward from affected node
│   ├── model/
│   │   ├── RiskScoreEvent.java
│   │   └── AlertEvent.java
│   ├── publisher/
│   │   └── RiskEventPublisher.java
│   └── error/
│       └── DeadLetterHandler.java               # Routes failures to DLQ
```

**Risk Scoring Formula:**

```
RiskScore(project, vuln) = CVSS_base
    × depth_decay(transitive_depth)
    × fan_out_multiplier(path_count)
    × freshness_weight(days_since_disclosure)

Where:
  depth_decay(d) = 1.0 / (1 + 0.3 * d)          # Decays with depth, never reaches zero
  fan_out_multiplier(p) = 1 + log2(p)             # Amplifies when multiple paths exist
  freshness_weight(d) = max(0.1, 1.0 - d/365)     # Recent vulns weighted higher

Project aggregate score = max(all individual RiskScores)
```

This formula captures the "hidden amplifier" effect: a moderate-severity vulnerability (CVSS 5.0) that appears through 8 different transitive paths has a higher effective risk than a high-severity vulnerability (CVSS 7.0) reachable through a single direct dependency.

---

### 3. Notification Service (`sentinel-notification`)

Consumes scored events and pushes real-time updates to connected dashboard clients via WebSocket.

**Responsibilities:**
- Consume risk scores and alerts from Kafka
- Maintain WebSocket sessions to connected React clients
- Aggregate scores per project for dashboard summary views
- Apply alert thresholds (configurable per project) to filter noise
- Cache recent scores in Redis for dashboard initialization on connect

**Key Classes:**
```
sentinel-notification/
├── src/main/java/com/sentinel/notification/
│   ├── NotificationApplication.java
│   ├── config/
│   │   ├── KafkaConsumerConfig.java
│   │   └── WebSocketConfig.java
│   ├── consumer/
│   │   ├── RiskScoreConsumer.java
│   │   └── AlertConsumer.java
│   ├── websocket/
│   │   ├── DashboardWebSocketHandler.java       # Manages client sessions
│   │   └── WebSocketSessionRegistry.java        # Tracks active connections
│   ├── aggregator/
│   │   └── ProjectScoreAggregator.java          # Rolling score summary per project
│   ├── threshold/
│   │   └── AlertThresholdFilter.java            # Configurable alert levels
│   └── cache/
│       └── RecentScoreCache.java                # Redis-backed recent scores
```

**WebSocket Protocol:**

The server pushes JSON messages to connected clients:

```json
{
  "type": "RISK_SCORE_UPDATE",
  "projectId": "my-api-service",
  "payload": {
    "aggregateScore": 7.2,
    "criticalCount": 1,
    "highCount": 3,
    "affectedDependencies": ["log4j-core:2.14.1", "commons-text:1.9"],
    "timestamp": "2026-06-01T14:30:00Z"
  }
}
```

```json
{
  "type": "ALERT",
  "projectId": "my-api-service",
  "payload": {
    "severity": "CRITICAL",
    "cveId": "CVE-2026-12345",
    "package": "log4j-core",
    "message": "Critical RCE vulnerability — 4 transitive paths to your project",
    "riskScore": 9.1,
    "timestamp": "2026-06-01T14:30:05Z"
  }
}
```

---

### 4. React Dashboard (`sentinel-dashboard`)

A real-time single-page application that visualizes the risk posture of monitored projects.

**Views:**

| View                | Description                                                                                     |
| ------------------- | ----------------------------------------------------------------------------------------------- |
| **Overview**        | All monitored projects as cards with aggregate risk scores, color-coded severity, trend arrows   |
| **Project Detail**  | Drill-down into a single project: dependency graph visualization, list of active vulnerabilities |
| **Dependency Graph**| Interactive D3.js force-directed graph showing the full dependency tree with risk-colored nodes  |
| **Event Timeline**  | Chronological feed of all ingested events (vulnerability disclosures, package updates, alerts)   |
| **Alerts**          | Filterable list of active alerts with severity, affected path, and recommended action            |

**Key Components:**
```
sentinel-dashboard/
├── src/
│   ├── App.tsx
│   ├── main.tsx
│   ├── hooks/
│   │   ├── useWebSocket.ts                      # WebSocket connection + reconnection
│   │   ├── useRiskScores.ts                     # Real-time score state management
│   │   └── useAlerts.ts                         # Alert state management
│   ├── components/
│   │   ├── layout/
│   │   │   ├── Sidebar.tsx
│   │   │   └── Header.tsx
│   │   ├── overview/
│   │   │   ├── ProjectCard.tsx                  # Risk summary card per project
│   │   │   ├── ProjectGrid.tsx                  # Grid of all project cards
│   │   │   └── RiskBadge.tsx                    # Color-coded severity badge
│   │   ├── detail/
│   │   │   ├── ProjectDetail.tsx                # Main detail view
│   │   │   ├── VulnerabilityList.tsx            # Active vulns for a project
│   │   │   └── RiskTrend.tsx                    # Score over time chart
│   │   ├── graph/
│   │   │   ├── DependencyGraphView.tsx          # D3.js force-directed graph
│   │   │   ├── GraphNode.tsx                    # Individual node rendering
│   │   │   └── GraphControls.tsx                # Zoom, filter, highlight
│   │   ├── timeline/
│   │   │   ├── EventTimeline.tsx                # Scrollable event feed
│   │   │   └── EventCard.tsx                    # Individual event rendering
│   │   └── alerts/
│   │       ├── AlertList.tsx                    # Filterable alert table
│   │       └── AlertDetail.tsx                  # Expanded alert with path info
│   ├── services/
│   │   ├── websocketService.ts                  # WebSocket client singleton
│   │   └── apiService.ts                        # REST calls for historical data
│   ├── types/
│   │   ├── events.ts                            # Event type definitions
│   │   ├── risk.ts                              # Risk score types
│   │   └── graph.ts                             # Graph node/edge types
│   └── utils/
│       ├── riskColors.ts                        # Score-to-color mapping
│       └── formatters.ts                        # Date, score formatting
├── public/
├── package.json
├── tsconfig.json
├── vite.config.ts
└── tailwind.config.js
```

**WebSocket Reconnection Strategy:**
- Initial connection on app load
- Exponential backoff on disconnect (1s, 2s, 4s, 8s, max 30s)
- On reconnect: fetch latest scores via REST to fill any gaps, then resume WebSocket stream

---

## Data Model (PostgreSQL)

```sql
-- Monitored projects
CREATE TABLE projects (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(255) NOT NULL UNIQUE,
    repository_url  VARCHAR(512),
    ecosystem       VARCHAR(50) NOT NULL,  -- 'maven', 'npm'
    manifest_path   VARCHAR(512),          -- 'pom.xml', 'package.json'
    created_at      TIMESTAMP DEFAULT NOW()
);

-- Dependency snapshots (rebuilt on each dependency.updated event)
CREATE TABLE dependency_snapshots (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id      UUID REFERENCES projects(id),
    resolved_at     TIMESTAMP DEFAULT NOW(),
    dependency_tree JSONB NOT NULL          -- Full resolved tree
);

-- Known vulnerabilities
CREATE TABLE vulnerabilities (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cve_id          VARCHAR(50) UNIQUE NOT NULL,
    package_name    VARCHAR(255) NOT NULL,
    affected_range  VARCHAR(255),           -- e.g., '>=2.0.0, <2.17.1'
    cvss_score      DECIMAL(3,1),
    severity        VARCHAR(20),            -- CRITICAL, HIGH, MEDIUM, LOW
    description     TEXT,
    published_at    TIMESTAMP,
    source          VARCHAR(50)             -- 'NVD', 'OSV', 'GITHUB'
);

-- Risk score history (for trend visualization)
CREATE TABLE risk_scores (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id      UUID REFERENCES projects(id),
    vulnerability_id UUID REFERENCES vulnerabilities(id),
    score           DECIMAL(4,2) NOT NULL,
    transitive_depth INTEGER,
    path_count      INTEGER,
    scored_at       TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_risk_scores_project_time ON risk_scores(project_id, scored_at DESC);

-- Active alerts
CREATE TABLE alerts (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id      UUID REFERENCES projects(id),
    vulnerability_id UUID REFERENCES vulnerabilities(id),
    severity        VARCHAR(20) NOT NULL,
    message         TEXT,
    risk_score      DECIMAL(4,2),
    acknowledged    BOOLEAN DEFAULT FALSE,
    created_at      TIMESTAMP DEFAULT NOW()
);
```

---

## Project Structure

```
sentinel/
├── sentinel-ingestion/              # Spring Boot — event ingestion
│   ├── src/main/java/...
│   ├── src/test/java/...
│   ├── pom.xml
│   └── Dockerfile
├── sentinel-analysis/               # Spring Boot — risk analysis
│   ├── src/main/java/...
│   ├── src/test/java/...
│   ├── pom.xml
│   └── Dockerfile
├── sentinel-notification/           # Spring Boot — WebSocket push
│   ├── src/main/java/...
│   ├── src/test/java/...
│   ├── pom.xml
│   └── Dockerfile
├── sentinel-dashboard/              # React + TypeScript
│   ├── src/...
│   ├── package.json
│   ├── Dockerfile
│   └── vite.config.ts
├── sentinel-common/                 # Shared event models and utils
│   ├── src/main/java/...
│   └── pom.xml
├── docker-compose.yml               # Full stack: Kafka, PostgreSQL, Redis, all services
├── docker-compose.dev.yml           # Dev overrides (hot reload, debug ports)
├── pom.xml                          # Parent POM (multi-module Maven project)
├── Makefile
├── .env.example
└── README.md
```

---

## Getting Started

### Prerequisites

| Tool           | Version  |
| -------------- | -------- |
| Java           | 21       |
| Maven          | 3.9+     |
| Node.js        | 20+      |
| Docker         | 24+      |
| Docker Compose | 2.20+    |

### Quick Start

```bash
# Clone the repository
git clone https://github.com/<your-username>/sentinel.git
cd sentinel

# Start infrastructure (Kafka, PostgreSQL, Redis)
docker compose up -d kafka postgres redis

# Build all backend services
mvn clean package -DskipTests

# Run database migrations
mvn -pl sentinel-analysis flyway:migrate

# Start all services
docker compose up -d

# Open the dashboard
open http://localhost:3000
```

### Development Mode

```bash
# Start infrastructure only
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d kafka postgres redis

# Run each service individually with hot reload
cd sentinel-ingestion && mvn spring-boot:run
cd sentinel-analysis && mvn spring-boot:run
cd sentinel-notification && mvn spring-boot:run

# Start React dev server
cd sentinel-dashboard && npm install && npm run dev
```

### Run Tests

```bash
# Backend tests (uses Testcontainers for Kafka and PostgreSQL)
mvn test

# Frontend tests
cd sentinel-dashboard && npm test

# Integration tests (full pipeline)
mvn verify -Pintegration
```

### Simulate Events

For development and demos, you can inject sample events without external feeds:

```bash
# Simulate a critical vulnerability disclosure
curl -X POST http://localhost:8081/api/ingest/vulnerability \
  -H "Content-Type: application/json" \
  -d '{
    "cveId": "CVE-2026-99999",
    "packageName": "com.example:vulnerable-lib",
    "affectedRange": ">=1.0.0, <1.5.3",
    "cvssScore": 9.8,
    "severity": "CRITICAL",
    "description": "Remote code execution via crafted input"
  }'

# Simulate a dependency update
curl -X POST http://localhost:8081/api/ingest/dependency-update \
  -H "Content-Type: application/json" \
  -d '{
    "projectId": "my-api-service",
    "packageName": "com.example:vulnerable-lib",
    "previousVersion": "1.4.0",
    "newVersion": "1.5.3"
  }'
```

---

## Configuration

All services use Spring Boot externalized configuration. Key properties:

```yaml
# sentinel-ingestion/src/main/resources/application.yml
spring:
  kafka:
    bootstrap-servers: ${KAFKA_BOOTSTRAP_SERVERS:localhost:9092}
    producer:
      acks: all
      retries: 3
      key-serializer: org.apache.kafka.common.serialization.StringSerializer
      value-serializer: org.springframework.kafka.support.serializer.JsonSerializer

sentinel:
  ingestion:
    nvd-poll-interval: PT1H          # Poll NVD every hour
    osv-poll-interval: PT30M         # Poll OSV every 30 minutes
    dedup-ttl: PT24H                 # Ignore duplicate events within 24h
```

```yaml
# sentinel-analysis/src/main/resources/application.yml
sentinel:
  analysis:
    scoring:
      depth-decay-factor: 0.3
      freshness-window-days: 365
      alert-threshold: 7.0           # Score >= 7.0 triggers alert
```

---

## Roadmap

- [x] Phase 1: Project scaffolding, Kafka topology, Docker Compose
- [ ] Phase 2: Ingestion service (webhook endpoints, feed pollers, event normalization)
- [ ] Phase 3: Analysis service (dependency resolution, graph builder, risk scoring)
- [ ] Phase 4: Notification service (Kafka consumers, WebSocket push, Redis cache)
- [ ] Phase 5: React dashboard (overview, project detail, event timeline)
- [ ] Phase 6: Dependency graph visualization (D3.js interactive graph)
- [ ] Phase 7: Integration tests with Testcontainers
- [ ] Phase 8: Demo data generator and walkthrough documentation

---

## License

MIT
