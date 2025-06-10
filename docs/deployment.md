# Deployment Guide

## Overview

The OAuth2 Service is designed as a **cloud-native microservice** optimized for containerized deployment on **Kubernetes**. This guide covers everything from local development to production deployment in orchestrated environments.

## 🐳 Containerization

### Dockerfile

The service uses a multi-stage build for optimal production images:

```dockerfile
# Build stage
FROM python:3.11-slim as builder

# Set build arguments
ARG BUILDPLATFORM
ARG TARGETPLATFORM

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install uv package manager
RUN pip install uv

# Copy dependency files
COPY pyproject.toml uv.lock ./

# Install dependencies
RUN uv sync --frozen --no-dev

# Production stage
FROM python:3.11-slim as production

# Create non-root user
RUN groupadd -r oauth2 && useradd -r -g oauth2 oauth2

# Set working directory
WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*

# Copy virtual environment from builder
COPY --from=builder /app/.venv /app/.venv

# Copy application code
COPY app/ ./app/
COPY --chown=oauth2:oauth2 . .

# Create logs directory
RUN mkdir -p logs && chown oauth2:oauth2 logs

# Switch to non-root user
USER oauth2

# Set environment variables
ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONPATH="/app"
ENV PYTHONUNBUFFERED=1

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Expose port
EXPOSE 8000

# Run application
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

### Docker Compose for Development

```yaml
# docker-compose.yml
version: '3.8'

services:
  oauth2-service:
    build: .
    ports:
      - "8000:8000"
    environment:
      - DATABASE_URL=postgresql+asyncpg://oauth2_user:oauth2_pass@postgres:5432/oauth2_db
      - REDIS_URL=redis://redis:6379
      - SECRET_KEY=${SECRET_KEY:-development-secret-key}
      - LOG_LEVEL=INFO
      - LOG_FORMAT=json
      - ENVIRONMENT=development
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    volumes:
      - ./logs:/app/logs
    networks:
      - oauth2-network
    restart: unless-stopped

  postgres:
    image: postgres:15-alpine
    environment:
      - POSTGRES_USER=oauth2_user
      - POSTGRES_PASSWORD=oauth2_pass
      - POSTGRES_DB=oauth2_db
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./scripts/init-db.sql:/docker-entrypoint-initdb.d/init.sql
    networks:
      - oauth2-network
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U oauth2_user -d oauth2_db"]
      interval: 10s
      timeout: 5s
      retries: 5
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
    networks:
      - oauth2-network
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5
    restart: unless-stopped

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf
      - ./nginx/ssl:/etc/nginx/ssl
    depends_on:
      - oauth2-service
    networks:
      - oauth2-network
    restart: unless-stopped

volumes:
  postgres_data:
  redis_data:

networks:
  oauth2-network:
    driver: bridge
```

### Environment Configuration

```bash
# .env.production
DATABASE_URL=postgresql+asyncpg://oauth2_user:secure_password@postgres:5432/oauth2_db
REDIS_URL=redis://redis:6379/0
SECRET_KEY=your-super-secure-secret-key-here
ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_MINUTES=10080
LOG_LEVEL=INFO
LOG_FORMAT=json
ENVIRONMENT=production
APP_VERSION=1.0.0

# OAuth2 configuration
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret

# Security settings
CORS_ORIGINS=["https://your-frontend.com"]
ALLOWED_HOSTS=["oauth2-service.com", "api.oauth2-service.com"]
```

## ☸️ Kubernetes Deployment

### Namespace and ConfigMap

```yaml
# k8s/namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: oauth2-system
  labels:
    app.kubernetes.io/name: oauth2-service
    app.kubernetes.io/component: namespace

---
# k8s/configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: oauth2-config
  namespace: oauth2-system
data:
  LOG_LEVEL: "INFO"
  LOG_FORMAT: "json"
  ENVIRONMENT: "production"
  ACCESS_TOKEN_EXPIRE_MINUTES: "30"
  REFRESH_TOKEN_EXPIRE_MINUTES: "10080"
  CORS_ORIGINS: '["https://app.example.com"]'
```

### Secrets Management

```yaml
# k8s/secrets.yaml
apiVersion: v1
kind: Secret
metadata:
  name: oauth2-secrets
  namespace: oauth2-system
type: Opaque
data:
  # Base64 encoded values
  DATABASE_URL: cG9zdGdyZXNxbCthc3luY3BnOi8vb2F1dGgyX3VzZXI6c2VjdXJlX3Bhc3NAcG9zdGdyZXM6NTQzMi9vYXV0aDJfZGI=
  REDIS_URL: cmVkaXM6Ly9yZWRpczo2Mzc5LzA=
  SECRET_KEY: eW91ci1zdXBlci1zZWN1cmUtc2VjcmV0LWtleS1oZXJl
  GOOGLE_CLIENT_ID: eW91ci1nb29nbGUtY2xpZW50LWlk
  GOOGLE_CLIENT_SECRET: eW91ci1nb29nbGUtY2xpZW50LXNlY3JldA==

---
# For automatic secret creation from environment
apiVersion: external-secrets.io/v1beta1
kind: SecretStore
metadata:
  name: vault-backend
  namespace: oauth2-system
spec:
  provider:
    vault:
      server: "https://vault.example.com"
      path: "secret"
      version: "v2"
      auth:
        kubernetes:
          mountPath: "kubernetes"
          role: "oauth2-service"
```

### Application Deployment

```yaml
# k8s/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: oauth2-service
  namespace: oauth2-system
  labels:
    app.kubernetes.io/name: oauth2-service
    app.kubernetes.io/component: api
    app.kubernetes.io/version: "1.0.0"
spec:
  replicas: 3
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 0
  selector:
    matchLabels:
      app.kubernetes.io/name: oauth2-service
      app.kubernetes.io/component: api
  template:
    metadata:
      labels:
        app.kubernetes.io/name: oauth2-service
        app.kubernetes.io/component: api
        app.kubernetes.io/version: "1.0.0"
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "8000"
        prometheus.io/path: "/metrics"
    spec:
      serviceAccountName: oauth2-service
      securityContext:
        runAsNonRoot: true
        runAsUser: 1001
        fsGroup: 1001
      containers:
      - name: oauth2-service
        image: oauth2-service:1.0.0
        imagePullPolicy: IfNotPresent
        ports:
        - name: http
          containerPort: 8000
          protocol: TCP
        envFrom:
        - configMapRef:
            name: oauth2-config
        - secretRef:
            name: oauth2-secrets
        env:
        - name: POD_NAME
          valueFrom:
            fieldRef:
              fieldPath: metadata.name
        - name: POD_NAMESPACE
          valueFrom:
            fieldRef:
              fieldPath: metadata.namespace
        - name: POD_IP
          valueFrom:
            fieldRef:
              fieldPath: status.podIP
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health
            port: http
          initialDelaySeconds: 30
          periodSeconds: 10
          timeoutSeconds: 5
          failureThreshold: 3
        readinessProbe:
          httpGet:
            path: /health/ready
            port: http
          initialDelaySeconds: 5
          periodSeconds: 5
          timeoutSeconds: 3
          failureThreshold: 3
        startupProbe:
          httpGet:
            path: /health/startup
            port: http
          initialDelaySeconds: 10
          periodSeconds: 10
          timeoutSeconds: 5
          failureThreshold: 30
        volumeMounts:
        - name: logs
          mountPath: /app/logs
        - name: tmp
          mountPath: /tmp
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop:
            - ALL
      volumes:
      - name: logs
        emptyDir: {}
      - name: tmp
        emptyDir: {}
      terminationGracePeriodSeconds: 30

---
# k8s/service-account.yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: oauth2-service
  namespace: oauth2-system
  labels:
    app.kubernetes.io/name: oauth2-service
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: oauth2-service
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: oauth2-service
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: oauth2-service
subjects:
- kind: ServiceAccount
  name: oauth2-service
  namespace: oauth2-system
```

### Service and Ingress

```yaml
# k8s/service.yaml
apiVersion: v1
kind: Service
metadata:
  name: oauth2-service
  namespace: oauth2-system
  labels:
    app.kubernetes.io/name: oauth2-service
    app.kubernetes.io/component: api
spec:
  type: ClusterIP
  ports:
  - port: 80
    targetPort: http
    protocol: TCP
    name: http
  selector:
    app.kubernetes.io/name: oauth2-service
    app.kubernetes.io/component: api

---
# k8s/ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: oauth2-service
  namespace: oauth2-system
  labels:
    app.kubernetes.io/name: oauth2-service
    app.kubernetes.io/component: ingress
  annotations:
    nginx.ingress.kubernetes.io/rewrite-target: /
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
    nginx.ingress.kubernetes.io/cors-allow-origin: "https://app.example.com"
    nginx.ingress.kubernetes.io/cors-allow-methods: "GET, POST, PUT, DELETE, OPTIONS"
    nginx.ingress.kubernetes.io/cors-allow-headers: "Authorization, Content-Type"
    nginx.ingress.kubernetes.io/rate-limit: "100"
    nginx.ingress.kubernetes.io/rate-limit-window: "1m"
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
spec:
  ingressClassName: nginx
  tls:
  - hosts:
    - api.oauth2-service.com
    secretName: oauth2-service-tls
  rules:
  - host: api.oauth2-service.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: oauth2-service
            port:
              number: 80
```

### Database and Redis

```yaml
# k8s/postgres.yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: postgres
  namespace: oauth2-system
spec:
  serviceName: postgres
  replicas: 1
  selector:
    matchLabels:
      app: postgres
  template:
    metadata:
      labels:
        app: postgres
    spec:
      containers:
      - name: postgres
        image: postgres:15-alpine
        env:
        - name: POSTGRES_DB
          value: "oauth2_db"
        - name: POSTGRES_USER
          value: "oauth2_user"
        - name: POSTGRES_PASSWORD
          valueFrom:
            secretKeyRef:
              name: postgres-secret
              key: password
        ports:
        - containerPort: 5432
        volumeMounts:
        - name: postgres-storage
          mountPath: /var/lib/postgresql/data
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "1Gi"
            cpu: "500m"
  volumeClaimTemplates:
  - metadata:
      name: postgres-storage
    spec:
      accessModes: ["ReadWriteOnce"]
      resources:
        requests:
          storage: 10Gi

---
apiVersion: v1
kind: Service
metadata:
  name: postgres
  namespace: oauth2-system
spec:
  selector:
    app: postgres
  ports:
  - port: 5432
    targetPort: 5432

---
# k8s/redis.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: redis
  namespace: oauth2-system
spec:
  replicas: 1
  selector:
    matchLabels:
      app: redis
  template:
    metadata:
      labels:
        app: redis
    spec:
      containers:
      - name: redis
        image: redis:7-alpine
        ports:
        - containerPort: 6379
        resources:
          requests:
            memory: "128Mi"
            cpu: "100m"
          limits:
            memory: "256Mi"
            cpu: "200m"
        volumeMounts:
        - name: redis-storage
          mountPath: /data
      volumes:
      - name: redis-storage
        emptyDir: {}

---
apiVersion: v1
kind: Service
metadata:
  name: redis
  namespace: oauth2-system
spec:
  selector:
    app: redis
  ports:
  - port: 6379
    targetPort: 6379
```

## 🔧 Microservice Architecture

### Service Mesh Integration

```yaml
# k8s/istio/virtual-service.yaml
apiVersion: networking.istio.io/v1beta1
kind: VirtualService
metadata:
  name: oauth2-service
  namespace: oauth2-system
spec:
  hosts:
  - api.oauth2-service.com
  gateways:
  - oauth2-gateway
  http:
  - match:
    - uri:
        prefix: "/api/v1/auth"
    route:
    - destination:
        host: oauth2-service
        port:
          number: 80
    timeout: 30s
    retries:
      attempts: 3
      perTryTimeout: 10s
  - match:
    - uri:
        prefix: "/health"
    route:
    - destination:
        host: oauth2-service
        port:
          number: 80

---
apiVersion: networking.istio.io/v1beta1
kind: DestinationRule
metadata:
  name: oauth2-service
  namespace: oauth2-system
spec:
  host: oauth2-service
  trafficPolicy:
    connectionPool:
      tcp:
        maxConnections: 10
      http:
        http1MaxPendingRequests: 10
        maxRequestsPerConnection: 10
    circuitBreaker:
      consecutiveErrors: 3
      interval: 30s
      baseEjectionTime: 30s
    loadBalancer:
      simple: LEAST_CONN
```

### Horizontal Pod Autoscaler

```yaml
# k8s/hpa.yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: oauth2-service-hpa
  namespace: oauth2-system
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: oauth2-service
  minReplicas: 3
  maxReplicas: 20
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
  - type: Pods
    pods:
      metric:
        name: http_requests_per_second
      target:
        type: AverageValue
        averageValue: "100"
  behavior:
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
      - type: Percent
        value: 10
        periodSeconds: 60
    scaleUp:
      stabilizationWindowSeconds: 60
      policies:
      - type: Percent
        value: 50
        periodSeconds: 30
```

### Pod Disruption Budget

```yaml
# k8s/pdb.yaml
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: oauth2-service-pdb
  namespace: oauth2-system
spec:
  minAvailable: 2
  selector:
    matchLabels:
      app.kubernetes.io/name: oauth2-service
      app.kubernetes.io/component: api
```

## 📊 Monitoring and Observability

### Prometheus ServiceMonitor

```yaml
# k8s/monitoring/service-monitor.yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: oauth2-service
  namespace: oauth2-system
  labels:
    app.kubernetes.io/name: oauth2-service
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: oauth2-service
  endpoints:
  - port: http
    path: /metrics
    interval: 30s
    scrapeTimeout: 10s
```

### Grafana Dashboard

```json
{
  "dashboard": {
    "title": "OAuth2 Service Metrics",
    "panels": [
      {
        "title": "Request Rate",
        "type": "stat",
        "targets": [
          {
            "expr": "rate(http_requests_total{service=\"oauth2-service\"}[5m])",
            "legendFormat": "Requests/sec"
          }
        ]
      },
      {
        "title": "Response Time",
        "type": "stat",
        "targets": [
          {
            "expr": "histogram_quantile(0.95, rate(http_request_duration_seconds_bucket{service=\"oauth2-service\"}[5m]))",
            "legendFormat": "95th percentile"
          }
        ]
      },
      {
        "title": "Error Rate",
        "type": "stat",
        "targets": [
          {
            "expr": "rate(http_requests_total{service=\"oauth2-service\",status=~\"5..\"}[5m]) / rate(http_requests_total{service=\"oauth2-service\"}[5m])",
            "legendFormat": "Error rate"
          }
        ]
      }
    ]
  }
}
```

### Logging with Fluentd

```yaml
# k8s/logging/fluentd.yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: fluentd
  namespace: oauth2-system
spec:
  selector:
    matchLabels:
      name: fluentd
  template:
    metadata:
      labels:
        name: fluentd
    spec:
      serviceAccount: fluentd
      containers:
      - name: fluentd
        image: fluent/fluentd-kubernetes-daemonset:v1-debian-elasticsearch
        env:
        - name: FLUENT_ELASTICSEARCH_HOST
          value: "elasticsearch.logging.svc.cluster.local"
        - name: FLUENT_ELASTICSEARCH_PORT
          value: "9200"
        volumeMounts:
        - name: varlog
          mountPath: /var/log
        - name: varlibdockercontainers
          mountPath: /var/lib/docker/containers
          readOnly: true
        - name: fluent-conf
          mountPath: /fluentd/etc/fluent.conf
          subPath: fluent.conf
      volumes:
      - name: varlog
        hostPath:
          path: /var/log
      - name: varlibdockercontainers
        hostPath:
          path: /var/lib/docker/containers
      - name: fluent-conf
        configMap:
          name: fluentd-config
```

## 🚀 Deployment Strategies

### Blue-Green Deployment

```yaml
# k8s/blue-green/deployment-blue.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: oauth2-service-blue
  namespace: oauth2-system
  labels:
    app.kubernetes.io/name: oauth2-service
    app.kubernetes.io/component: api
    app.kubernetes.io/version: "1.0.0"
    deployment: blue
spec:
  replicas: 3
  selector:
    matchLabels:
      app.kubernetes.io/name: oauth2-service
      deployment: blue
  template:
    metadata:
      labels:
        app.kubernetes.io/name: oauth2-service
        app.kubernetes.io/component: api
        deployment: blue
    spec:
      # ... same as regular deployment

---
# Switch traffic script
#!/bin/bash
# switch-traffic.sh

# Update service selector to point to green deployment
kubectl patch service oauth2-service -n oauth2-system -p '{"spec":{"selector":{"deployment":"green"}}}'

# Wait for rollout to complete
kubectl rollout status deployment/oauth2-service-green -n oauth2-system

# Scale down blue deployment
kubectl scale deployment oauth2-service-blue --replicas=0 -n oauth2-system
```

### Canary Deployment with Istio

```yaml
# k8s/canary/virtual-service-canary.yaml
apiVersion: networking.istio.io/v1beta1
kind: VirtualService
metadata:
  name: oauth2-service-canary
  namespace: oauth2-system
spec:
  hosts:
  - api.oauth2-service.com
  http:
  - match:
    - headers:
        canary:
          exact: "true"
    route:
    - destination:
        host: oauth2-service
        subset: v2
  - route:
    - destination:
        host: oauth2-service
        subset: v1
      weight: 90
    - destination:
        host: oauth2-service
        subset: v2
      weight: 10

---
apiVersion: networking.istio.io/v1beta1
kind: DestinationRule
metadata:
  name: oauth2-service-canary
  namespace: oauth2-system
spec:
  host: oauth2-service
  subsets:
  - name: v1
    labels:
      version: v1
  - name: v2
    labels:
      version: v2
```

## 🔐 Security Best Practices

### Network Policies

```yaml
# k8s/security/network-policy.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: oauth2-service-network-policy
  namespace: oauth2-system
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: oauth2-service
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: ingress-nginx
    ports:
    - protocol: TCP
      port: 8000
  egress:
  - to:
    - podSelector:
        matchLabels:
          app: postgres
    ports:
    - protocol: TCP
      port: 5432
  - to:
    - podSelector:
        matchLabels:
          app: redis
    ports:
    - protocol: TCP
      port: 6379
  - to: []
    ports:
    - protocol: TCP
      port: 443  # HTTPS outbound
    - protocol: TCP
      port: 53   # DNS
    - protocol: UDP
      port: 53   # DNS
```

### Security Context

```yaml
# Security scanning with Trivy
apiVersion: batch/v1
kind: Job
metadata:
  name: trivy-scan
  namespace: oauth2-system
spec:
  template:
    spec:
      restartPolicy: Never
      containers:
      - name: trivy
        image: aquasec/trivy:latest
        command:
        - trivy
        - image
        - --exit-code
        - "1"
        - --severity
        - HIGH,CRITICAL
        - oauth2-service:1.0.0
```

## 📋 CI/CD Pipeline

### GitHub Actions Workflow

```yaml
# .github/workflows/deploy.yml
name: Deploy to Kubernetes

on:
  push:
    branches: [main]
    tags: ['v*']

env:
  REGISTRY: ghcr.io
  IMAGE_NAME: oauth2-service

jobs:
  test:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:15
        env:
          POSTGRES_PASSWORD: postgres
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
      redis:
        image: redis:7
        options: >-
          --health-cmd "redis-cli ping"
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5

    steps:
    - uses: actions/checkout@v4
    
    - name: Install uv
      uses: astral-sh/setup-uv@v2
      with:
        version: "latest"
    
    - name: Set up Python
      run: uv python install 3.11
    
    - name: Install dependencies
      run: uv sync
    
    - name: Run tests
      run: uv run pytest --cov=app --cov-report=xml
      env:
        DATABASE_URL: postgresql+asyncpg://postgres:postgres@localhost:5432/postgres
        REDIS_URL: redis://localhost:6379
    
    - name: Upload coverage to Codecov
      uses: codecov/codecov-action@v3

  build-and-push:
    needs: test
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write

    steps:
    - name: Checkout repository
      uses: actions/checkout@v4

    - name: Log in to Container Registry
      uses: docker/login-action@v3
      with:
        registry: ${{ env.REGISTRY }}
        username: ${{ github.actor }}
        password: ${{ secrets.GITHUB_TOKEN }}

    - name: Extract metadata
      id: meta
      uses: docker/metadata-action@v5
      with:
        images: ${{ env.REGISTRY }}/${{ github.repository }}/${{ env.IMAGE_NAME }}

    - name: Build and push Docker image
      uses: docker/build-push-action@v5
      with:
        context: .
        push: true
        tags: ${{ steps.meta.outputs.tags }}
        labels: ${{ steps.meta.outputs.labels }}

  deploy:
    needs: build-and-push
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    
    steps:
    - name: Checkout repository
      uses: actions/checkout@v4
    
    - name: Configure kubectl
      uses: azure/k8s-set-context@v3
      with:
        method: kubeconfig
        kubeconfig: ${{ secrets.KUBE_CONFIG }}
    
    - name: Deploy to Kubernetes
      run: |
        # Update image tag in deployment
        sed -i "s|oauth2-service:.*|${{ env.REGISTRY }}/${{ github.repository }}/${{ env.IMAGE_NAME }}:${{ github.sha }}|g" k8s/deployment.yaml
        
        # Apply all manifests
        kubectl apply -f k8s/namespace.yaml
        kubectl apply -f k8s/configmap.yaml
        kubectl apply -f k8s/secrets.yaml
        kubectl apply -f k8s/deployment.yaml
        kubectl apply -f k8s/service.yaml
        kubectl apply -f k8s/ingress.yaml
        kubectl apply -f k8s/hpa.yaml
        kubectl apply -f k8s/pdb.yaml
        
        # Wait for rollout
        kubectl rollout status deployment/oauth2-service -n oauth2-system --timeout=600s
```

### ArgoCD Application

```yaml
# k8s/argocd/application.yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: oauth2-service
  namespace: argocd
spec:
  project: default
  source:
    repoURL: https://github.com/your-org/oauth2-service
    targetRevision: HEAD
    path: k8s
  destination:
    server: https://kubernetes.default.svc
    namespace: oauth2-system
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
    syncOptions:
    - CreateNamespace=true
```

## 🔧 Deployment Commands

### Local Development

```bash
# Build and run locally
docker build -t oauth2-service:local .
docker-compose up -d

# View logs
docker-compose logs -f oauth2-service

# Scale services
docker-compose up -d --scale oauth2-service=3
```

### Kubernetes Deployment

```bash
# Create namespace and deploy
kubectl create namespace oauth2-system

# Deploy all components
kubectl apply -f k8s/

# Check deployment status
kubectl get pods -n oauth2-system
kubectl rollout status deployment/oauth2-service -n oauth2-system

# View logs
kubectl logs -f deployment/oauth2-service -n oauth2-system

# Port forward for testing
kubectl port-forward svc/oauth2-service 8000:80 -n oauth2-system

# Scale deployment
kubectl scale deployment oauth2-service --replicas=5 -n oauth2-system

# Rolling update
kubectl set image deployment/oauth2-service oauth2-service=oauth2-service:v1.1.0 -n oauth2-system
```

### Database Migrations

```bash
# Run migrations in Kubernetes
kubectl run migration-job --image=oauth2-service:1.0.0 --restart=Never -n oauth2-system -- alembic upgrade head

# Backup database
kubectl exec -it postgres-0 -n oauth2-system -- pg_dump -U oauth2_user oauth2_db > backup.sql
```

## 🌍 Multi-Environment Setup

### Development Environment

```yaml
# k8s/overlays/dev/kustomization.yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

resources:
- ../../base

patches:
- target:
    kind: Deployment
    name: oauth2-service
  patch: |-
    - op: replace
      path: /spec/replicas
      value: 1
    - op: replace
      path: /spec/template/spec/containers/0/resources/requests/memory
      value: "128Mi"
    - op: replace
      path: /spec/template/spec/containers/0/resources/requests/cpu
      value: "100m"

configMapGenerator:
- name: oauth2-config
  behavior: merge
  literals:
  - LOG_LEVEL=DEBUG
  - ENVIRONMENT=development
```

### Production Environment

```yaml
# k8s/overlays/prod/kustomization.yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

resources:
- ../../base

patches:
- target:
    kind: Deployment
    name: oauth2-service
  patch: |-
    - op: replace
      path: /spec/replicas
      value: 3
    - op: add
      path: /spec/template/spec/containers/0/securityContext
      value:
        readOnlyRootFilesystem: true
        runAsNonRoot: true

configMapGenerator:
- name: oauth2-config
  behavior: merge
  literals:
  - LOG_LEVEL=INFO
  - ENVIRONMENT=production
```

## 🔗 Next Steps

- **[Features & API](features-api.md)** - Review the capabilities you're deploying
- **[Project Structure](project-structure.md)** - Understand the application architecture
- **[Testing Guide](testing.md)** - Implement comprehensive testing before deployment
- **[Logging System](logging.md)** - Configure monitoring and observability

## 📚 Additional Resources

- [Kubernetes Best Practices](https://kubernetes.io/docs/concepts/best-practices/)
- [Docker Security](https://docs.docker.com/engine/security/)
- [Istio Service Mesh](https://istio.io/latest/docs/)
- [Prometheus Monitoring](https://prometheus.io/docs/)
- [ArgoCD GitOps](https://argo-cd.readthedocs.io/) 