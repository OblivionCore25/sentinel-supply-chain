.PHONY: help infra build test integration-test up demo down clean logs

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

infra: ## Start infrastructure only (Kafka, PostgreSQL, Redis, Apicurio, Traefik)
	docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d

build: ## Build all backend modules
	mvn clean package -DskipTests

test: ## Run all unit tests
	mvn test

integration-test: ## Run integration tests (requires Docker for Testcontainers)
	mvn verify -Pintegration

up: ## Start everything (all services + infrastructure)
	docker compose up -d --build

demo: ## Start everything with demo data seeder
	SPRING_PROFILES_ACTIVE=demo docker compose up -d --build

down: ## Stop all containers
	docker compose down

clean: ## Stop all containers and remove volumes
	docker compose down -v

logs: ## Tail all service logs
	docker compose logs -f --tail=50

logs-ingestion: ## Tail ingestion service logs
	docker compose logs -f --tail=50 sentinel-ingestion

logs-analysis: ## Tail analysis service logs
	docker compose logs -f --tail=50 sentinel-analysis

logs-notification: ## Tail notification service logs
	docker compose logs -f --tail=50 sentinel-notification

health: ## Check health of all services
	@echo "=== Ingestion ===" && curl -sf http://localhost:8081/actuator/health | jq .status || echo "DOWN"
	@echo "=== Analysis ===" && curl -sf http://localhost:8082/actuator/health | jq .status || echo "DOWN"
	@echo "=== Notification ===" && curl -sf http://localhost:8083/actuator/health | jq .status || echo "DOWN"
	@echo "=== Apicurio ===" && curl -sf http://localhost:8085/health | jq .status || echo "DOWN"
