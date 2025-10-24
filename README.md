# Centralized Authorization for Kubernetes: Securing North-South and East-West Traffic with Kyverno and Istio

## Introduction

In modern Kubernetes environments, securing API access has become increasingly complex. Traditional approaches rely on per-pod OPA (Open Policy Agent) sidecars, distributed policy bundles stored in S3, and complex synchronization mechanisms. This architecture introduces significant operational overhead—each pod requires its own sidecar container, policies must be built and distributed as bundles, and consistency across hundreds of services becomes a challenge.

What if you could eliminate the sidecars entirely while improving policy consistency and reducing operational complexity? A centralized Kyverno Authorization Server integrated with Istio service mesh offers exactly that. By leveraging Istio's external authorization filter and Kyverno's native Kubernetes policy engine, you can enforce fine-grained, JWT-based authorization for both north-south (ingress) and east-west (service-to-service) traffic—without adding a single sidecar to your workloads.

This guide demonstrates a production-ready authorization architecture that delivers **significant resource reduction**, **immediate policy updates**, and **centralized audit trails**—all while preserving your existing identity infrastructure. Whether you're facing cloud cost pressures, compliance requirements, or simply seeking operational simplicity at scale, this approach transforms authorization from a distributed burden into a streamlined, centrally-managed capability.

## Background: Understanding the Architecture

### The Sidecar Problem

Traditional OPA-based authorization in Kubernetes typically follows this pattern:

```
┌─────────────┐     ┌──────────────┐
│   Client    │────▶│    Istio     │
│             │     │   Gateway    │
└─────────────┘     └──────────────┘
                           │
                           ▼
                    ┌──────────────┐     ┌──────────────┐
                    │  Application │     │  OPA Sidecar │
                    │     Pod      │◀────│   + Bundle   │
                    └──────────────┘     └──────────────┘
```

**Challenges:**
- **Resource multiplication**: Every pod requires an additional OPA sidecar container, consuming memory and CPU
- **Bundle distribution**: Rego policies must be compiled, packaged, and distributed via S3 or similar storage
- **Update latency**: Policy changes require bundle rebuilds and pod restarts
- **Consistency risk**: Different pods may have different policy versions during rollouts
- **Operational overhead**: Managing N sidecars across hundreds of services

### The Centralized Alternative

With Kyverno Authorization Server and Istio:

```
┌─────────────┐    ┌──────────────┐    ┌─────────────────┐
│   Client    │───▶│    Istio     │───▶│  Kyverno Authz  │
│             │    │   Gateway/   │    │     Server      │
└─────────────┘    │   Proxy      │    └─────────────────┘
                   └──────────────┘             │
                           │                    ▼
                           ▼          ┌─────────────────┐
                   ┌──────────────┐   │   Keycloak      │
                   │  Application │   │   (JWT IdP)     │
                   │     Pod      │   └─────────────────┘
                   └──────────────┘
```

**Advantages:**
- **Sidecarless**: Authorization decisions happen at the Envoy proxy level via external auth
- **Centralized policies**: Kyverno ValidatingPolicy CRDs applied once, enforced everywhere
- **Immediate updates**: Policy changes take effect instantly—no pod restarts
- **Consistent enforcement**: Single source of truth for all authorization decisions
- **Native Kubernetes**: Policies are CRDs managed with kubectl and GitOps workflows

### How It Works

1. **Request Interception**: When a request arrives at the Istio ingress gateway or sidecar proxy, Istio's `AuthorizationPolicy` resource (with `action: CUSTOM`) intercepts it.

2. **External Authorization Call**: The Envoy proxy makes a gRPC call to the Kyverno Authorization Server, passing request attributes (headers, path, method, etc.).

3. **Policy Evaluation**: Kyverno evaluates the request against `ValidatingPolicy` CRDs, which can:
   - Extract and validate JWT tokens from the Authorization header
   - Verify token signatures using JWKS endpoints
   - Check token expiry and custom claims
   - Match requests by service, namespace, path, method, and headers
   - Return allow/deny decisions with custom status codes

4. **Decision Enforcement**: The proxy allows or denies the request based on Kyverno's decision, without the application ever seeing unauthorized requests.

5. **Logging and Observability**: All authorization decisions are logged centrally, providing clear audit trails.

### Key Technologies

**Kyverno**: A Kubernetes-native policy engine that uses CEL (Common Expression Language) for policy definitions. Originally focused on admission control, Kyverno now supports Envoy external authorization mode.

**Istio**: A service mesh that provides traffic management, security, and observability. The external authorization filter delegates auth decisions to external services.

**Keycloak**: An open-source identity and access management solution that issues standards-compliant JWT tokens. Can be replaced with any OIDC-compatible IdP (AWS Cognito, Auth0, etc.).

**CEL**: Common Expression Language—a non-Turing complete expression language designed for fast, safe evaluation in sandboxed environments. Used by Kyverno for policy logic.

## Prerequisites

Before proceeding, ensure you have the following:

### Required Knowledge
- **Kubernetes fundamentals**: Understanding of pods, services, namespaces, and CRDs
- **Service mesh concepts**: Familiarity with Istio or similar mesh technologies
- **JWT and OAuth2**: Basic understanding of token-based authentication
- **Policy-as-code**: Exposure to declarative policy concepts

### Required Tools

| Tool | Version | Purpose | Installation |
|------|---------|---------|--------------|
| **Docker** | 20.x+ | Container runtime | [Install Docker](https://docs.docker.com/get-docker/) |
| **kubectl** | 1.28+ | Kubernetes CLI | [Install kubectl](https://kubernetes.io/docs/tasks/tools/) |
| **Helm** | 3.12+ | Package manager | [Install Helm](https://helm.sh/docs/intro/install/) |
| **Kind** | 0.20+ | Local Kubernetes | [Install Kind](https://kind.sigs.k8s.io/docs/user/quick-start/) |
| **curl** | Any | HTTP client | Usually pre-installed |
| **jq** | 1.6+ | JSON processor | [Install jq](https://stedolan.github.io/jq/download/) |
| **Terraform** (optional) | 1.5+ | Keycloak config | [Install Terraform](https://developer.hashicorp.com/terraform/downloads) |

### Environment Setup

**Minimum resources for local development:**
- 8GB RAM
- 4 CPU cores
- 20GB free disk space

**Kubernetes cluster options:**
- **Local**: Kind, Minikube, or Docker Desktop
- **Cloud**: EKS, GKE, AKS with Istio support
- **On-premises**: Any Kubernetes 1.28+ cluster

### Verify Prerequisites

```bash
# Check tool versions
docker --version
kubectl version --client
helm version
kind --version
jq --version

# Verify Docker is running
docker ps

# Check available resources
docker system info | grep -E "CPUs|Total Memory"
```

## Step-by-Step Implementation

### Step 1: Create Local Kubernetes Cluster

We'll use Kind (Kubernetes in Docker) for a lightweight local cluster:

```bash
# Create cluster with specific Kubernetes version
kind create cluster --name authz-demo --image kindest/node:v1.31.0

# Verify cluster is running
kubectl cluster-info
kubectl get nodes
```

**What this does**: Creates a single-node Kubernetes cluster running in Docker. Kind is ideal for local development and testing without cloud costs.

**Expected output**:
```
Creating cluster "authz-demo" ...
 ✓ Ensuring node image (kindest/node:v1.31.0) 🖼
 ✓ Preparing nodes 📦
 ✓ Writing configuration 📜
 ✓ Starting control-plane 🕹️
 ✓ Installing CNI 🔌
 ✓ Installing StorageClass 💾
```

### Step 2: Deploy Keycloak Identity Provider

Keycloak will issue JWT tokens for testing. In production, use your existing IdP (AWS Cognito, Azure AD, Okta, etc.).

```bash
# Install Keycloak with Helm
kubectl create ns keycloak
kubectl create -f https://raw.githubusercontent.com/keycloak/keycloak-quickstarts/refs/heads/main/kubernetes/keycloak.yaml -n keycloak
```

**What this does**: Deploys Keycloak with an embedded PostgreSQL database. Keycloak will issue OIDC-compliant JWT tokens that our policies will validate.

**Access Keycloak** (in a separate terminal):
```bash
# Port forward to access Keycloak locally
kubectl port-forward -n keycloak svc/keycloak 8080:8080
```

Navigate to `http://localhost:8080` and login with `admin` / `admin`.

**Configure test realm and user** (using Terraform or manually):

```bash
# Option 1: Using Terraform (if keycloak.tf exists)
cd terraform
terraform init
terraform apply -auto-approve

# Option 2: Manual configuration via Keycloak Admin Console
# 1. Create realm: "demo-realm"
# 2. Create client: "demo-client" with client secret
# 3. Create user: "testuser" with password
# 4. Assign groups: "platform-admins", "developers"
```

### Step 3: Install Certificate Management

Kyverno requires TLS certificates for secure gRPC communication with Istio:

```bash
# Install cert-manager
helm install cert-manager \
  --namespace cert-manager --create-namespace \
  --wait \
  --repo https://charts.jetstack.io cert-manager \
  --set crds.enabled=true
```

**Create self-signed certificate issuer** (production should use Let's Encrypt or internal CA):

```bash
kubectl apply -f - <<EOF
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: selfsigned-issuer
spec:
  selfSigned: {}
EOF
```

**What this does**: cert-manager automates certificate lifecycle management. The ClusterIssuer creates self-signed certificates on demand for development purposes.

### Step 4: Install Kyverno Authorization Server

```bash
# Install Kyverno ValidatingPolicy CRD
kubectl apply -f \
  https://raw.githubusercontent.com/kyverno/kyverno/main/config/crds/policies.kyverno.io/policies.kyverno.io_validatingpolicies.yaml

# Install Kyverno Authorization Server
kubectl create ns kyverno
helm install kyverno-authz-server \
  --namespace kyverno \
  --wait \
  --repo https://kyverno.github.io/kyverno-envoy-plugin kyverno-authz-server \
  --values - <<EOF
certificates:
  certManager:
    issuerRef:
      group: cert-manager.io
      kind: ClusterIssuer
      name: selfsigned-issuer
EOF
```

**What this does**: 
- Installs the `ValidatingPolicy` CRD that defines authorization rules
- Deploys the Kyverno Authorization Server that evaluates policies
- Configures automatic TLS certificate generation

**Verify installation**:
```bash
kubectl get pods -n kyverno
kubectl get crd validatingpolicies.policies.kyverno.io
```

Expected: One running pod and the CRD installed.

### Step 5: Install Istio Service Mesh

Install Istio with the Kyverno external authorization provider configured:

```bash
# Install Istio base components
helm install istio-base \
  --namespace istio-system --create-namespace \
  --wait \
  --repo https://istio-release.storage.googleapis.com/charts base

# Install Istio control plane with Kyverno integration
helm install istiod \
  --namespace istio-system \
  --wait \
  --repo https://istio-release.storage.googleapis.com/charts istiod \
  --values - <<EOF
meshConfig:
  extensionProviders:
  - name: kyverno-authz-server
    envoyExtAuthzGrpc:
      service: kyverno-authz-server.kyverno.svc.cluster.local
      port: 9081
EOF
```

**What this does**: 
- Installs Istio's control plane (istiod)
- Configures the `kyverno-authz-server` as an external authorization provider
- Enables Envoy proxies to delegate authorization decisions to Kyverno

**Verify Istio installation**:
```bash
kubectl get pods -n istio-system
```

You should see the `istiod` pod running.

### Step 6: Deploy Test Application

We'll use HTTPBin, a simple HTTP request/response service:

```bash
# Create namespace and enable Istio injection
kubectl create ns app
kubectl label namespace app istio-injection=enabled

# Deploy HTTPBin
kubectl apply -n app -f https://raw.githubusercontent.com/istio/istio/release-1.24/samples/httpbin/httpbin.yaml

# Verify deployment
kubectl get pods -n app
```

**What this does**: Creates a test application with an Istio sidecar automatically injected. The sidecar will intercept requests and consult Kyverno for authorization.

**Expected output**: You'll see two containers in the HTTPBin pod—the application and the Istio proxy.

### Step 7: Configure Authorization Policies

Now we'll create the actual authorization rules.

**Create Istio AuthorizationPolicy** (instructs Istio to use Kyverno):

```bash
kubectl create -n app -f - <<EOF
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: kyverno-authz
spec:
  action: CUSTOM
  provider:
    name: kyverno-authz-server
  rules:
  - {}  # Intercept all requests
EOF
```

**What this does**: Tells Istio to call the Kyverno Authorization Server for every request to services in the `app` namespace.

**Create Kyverno ValidatingPolicy** (defines authorization logic):

```bash
kubectl apply -f kyverno/validating-policy.yaml
```

**What this does**: 
- **Token extraction**: Extracts Bearer token from Authorization header
- **JWT validation**: Validates token signature, issuer, and expiry using Keycloak's JWKS endpoint
- **Claim-based authorization**: Checks group membership for sensitive paths
- **Returns decisions**: Returns 401 (Unauthorized) for missing/invalid tokens, 403 (Forbidden) for insufficient permissions

**Policy breakdown**:

```yaml
variables:
  - name: token_issuer  # Where to get public keys
  - name: certs     # Downloaded certificates
  - name: authorization  # Parsed Authorization header
  - name: token     # Decoded JWT (or null)
```

```yaml
validations:
  - expression: >  # First rule: valid token required
      variables.token == null || !variables.token.Valid
        ? envoy.Denied(401).Response()
        : null
```

If `token` is null (no token provided) or `!token.Valid` (expired/invalid), return 401.

### Step 8: Test Authorization

**Set up test environment**:

```bash
# Create test pod
kubectl create ns test
kubectl run -i -t test-client --image=alpine --restart=Never -n test

# Inside the test pod, install tools
apk add curl jq
```

**Get a JWT token from Keycloak**:

```bash
# Set variables (adjust for your configuration)
ISSUER="http://keycloak.keycloak.svc.cluster.local:8080/realms/master"
TOKEN_ENDPOINT="$ISSUER/protocol/openid-connect/token"

# Get access token
ACCESS_TOKEN=$(curl -s -X POST $TOKEN_ENDPOINT \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=kube" \
  -d "client_secret=kube-client-secret" \
  -d "username=user-dev" \
  -d "password=user-dev" \
  -d "scope=openid profile email" | jq -r '.access_token')

echo $ACCESS_TOKEN
```

**Test with valid token** (should succeed):

```bash
curl -i -H "Authorization: Bearer $ACCESS_TOKEN" \
  http://httpbin.app:8000/get
```

Expected: HTTP 200 with response from HTTPBin.

**Test without token** (should fail with 401):

```bash
curl -i http://httpbin.app:8000/get
```

Expected: HTTP 401 Unauthorized.

**Test admin endpoint without admin group** (should fail with 403):

```bash
curl -i -H "Authorization: Bearer $ACCESS_TOKEN" \
  http://httpbin.app:8000/admin/users
```

Expected: HTTP 403 Forbidden (unless your user is in `platform-admins` group).

**Inspect the token**:

```bash
# Decode JWT (without validation)
echo $ACCESS_TOKEN | cut -d'.' -f2 | base64 -d | jq
```

You'll see claims like:
```json
{
  "sub": "user-id",
  "groups": ["kube-dev"],
  "iss": "http://keycloak.keycloak.svc.cluster.local:8080/realms/demo-realm",
  "exp": 1234567890,
  "iat": 1234564290
}
```

### Step 9: Advanced Policy Patterns

**Path-based authorization**:

```yaml
validations:
# Allow GET for all authenticated users
- expression: >
    object.attributes.request.http.method == "GET"
      ? envoy.Allowed().Response()
      : null

# POST/PUT/DELETE require write permissions
- expression: >
    object.attributes.request.http.method in ["POST", "PUT", "DELETE"] &&
    !("api-writers" in variables.token.Claims.groups)
      ? envoy.Denied(403).Response()
      : null
```

**Service-specific authorization**:

```yaml
validations:
# Only service accounts can call internal APIs
- expression: >
    object.attributes.request.http.path.startsWith("/internal/") &&
    !variables.token.Claims.client_id.startsWith("service-")
      ? envoy.Denied(403).Response()
      : null
```

**Time-based access**:

```yaml
validations:
# Check if token is about to expire (within 5 minutes)
- expression: >
    variables.token.Claims.exp < timestamp(now).getSeconds() + 300
      ? envoy.Denied(401).WithMessage("Token expiring soon").Response()
      : null
```

**Custom headers in response**:

```yaml
validations:
- expression: >
    variables.token.Valid
      ? envoy.Allowed()
          .WithHeader("X-Auth-User", variables.token.Claims.sub)
          .WithHeader("X-Auth-Groups", variables.token.Claims.groups.join(","))
          .Response()
      : envoy.Denied(401).Response()
```

This passes user identity to the application via headers.

### Step 10: Production Hardening

**Replace Keycloak with your production IdP**:

Update the `jwks_url` in your ValidatingPolicy:

```yaml
variables:
- name: jwks_url
  # For AWS Cognito:
  expression: string('https://cognito-idp.<region>.amazonaws.com/<user-pool-id>/.well-known/jwks.json')
  
  # For Azure AD:
  # expression: string('https://login.microsoftonline.com/<tenant-id>/discovery/v2.0/keys')
  
  # For Auth0:
  # expression: string('https://<your-domain>.auth0.com/.well-known/jwks.json')
```

**Enable TLS everywhere**:

```bash
# Use real certificates in production
# cert-manager with Let's Encrypt:
kubectl apply -f - <<EOF
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: your-email@example.com
    privateKeySecretRef:
      name: letsencrypt-prod
    solvers:
    - http01:
        ingress:
          class: istio
EOF
```

**Add resource limits**:

```yaml
# For Kyverno Authorization Server
resources:
  requests:
    memory: "256Mi"
    cpu: "200m"
  limits:
    memory: "512Mi"
    cpu: "500m"
```

**Configure high availability**:

```bash
# Scale Kyverno Authorization Server
kubectl scale deployment kyverno-authz-server -n kyverno --replicas=3

# Enable pod disruption budget
kubectl apply -f - <<EOF
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: kyverno-authz-server
  namespace: kyverno
spec:
  minAvailable: 2
  selector:
    matchLabels:
      app.kubernetes.io/name: kyverno-authz-server
EOF
```

**Monitoring and observability**:

```bash
# Enable Prometheus metrics
helm upgrade kyverno-authz-server \
  --namespace kyverno \
  --repo https://kyverno.github.io/kyverno-envoy-plugin kyverno-authz-server \
  --reuse-values \
  --set metrics.enabled=true
```

**Key metrics to track**:
- `authz_requests_total`: Total authorization requests
- `authz_request_duration_seconds`: Latency of authorization decisions
- `authz_denials_total`: Number of denied requests
- `jwt_validation_errors_total`: Token validation failures

**Centralized logging**:

```bash
# View authorization decisions
kubectl logs -n kyverno deployment/kyverno-authz-server -f

# Sample log entry
{
  "level": "info",
  "ts": "2025-10-13T10:15:30Z",
  "caller": "server/server.go:123",
  "msg": "authorization decision",
  "decision": "deny",
  "reason": "invalid_token",
  "path": "/api/users",
  "method": "GET",
  "user": "unknown",
  "status_code": 401
}
```

## Troubleshooting and FAQs

### Common Issues

#### Issue: Requests always return 500 Internal Server Error

**Symptoms**: All requests fail with HTTP 500, even with valid tokens.

**Diagnosis**:
```bash
# Check Kyverno Authorization Server logs
kubectl logs -n kyverno deployment/kyverno-authz-server

# Check Istio proxy logs
kubectl logs -n app deployment/httpbin -c istio-proxy
```

**Common causes**:
1. **Kyverno server not ready**: Wait for pod to be fully running
2. **Certificate issues**: Verify cert-manager created certificates
3. **Network connectivity**: Ensure Kyverno service is reachable from Istio

**Solution**:
```bash
# Verify service endpoints
kubectl get endpoints -n kyverno kyverno-authz-server

# Check certificate
kubectl get certificate -n kyverno

# Restart Kyverno if needed
kubectl rollout restart deployment/kyverno-authz-server -n kyverno
```

#### Issue: Valid tokens return 401 Unauthorized

**Symptoms**: Tokens that work with IdP validation fail in Kyverno.

**Diagnosis**:
```bash
# Check JWKS endpoint is reachable
kubectl run -it --rm debug --image=alpine --restart=Never -- sh
apk add curl
curl http://keycloak.keycloak.svc.cluster.local:8080/realms/demo-realm/protocol/openid-connect/certs
```

**Common causes**:
1. **JWKS URL mismatch**: Verify `jwks_url` matches your IdP
2. **Clock skew**: Token issued in future or expired due to time drift
3. **Audience mismatch**: Token intended for different audience

**Solution**:
```bash
# Update ValidatingPolicy with correct JWKS URL
kubectl edit validatingpolicy jwt-validation -n app

# Decode token to inspect claims
echo $ACCESS_TOKEN | cut -d'.' -f2 | base64 -d | jq

# Check for exp (expiry) and iat (issued at) timestamps
```

#### Issue: Policies not taking effect

**Symptoms**: Policy changes don't seem to apply to requests.

**Diagnosis**:
```bash
# Check if ValidatingPolicy is created
kubectl get validatingpolicy -n app

# Check policy status
kubectl describe validatingpolicy jwt-validation -n app
```

**Common causes**:
1. **Wrong namespace**: Policy created in different namespace than AuthorizationPolicy
2. **Syntax errors**: CEL expression syntax errors
3. **Cache**: Old policy still in effect

**Solution**:
```bash
# Validate CEL syntax
kubectl apply --dry-run=server -f policy.yaml

# Restart Kyverno to clear cache
kubectl rollout restart deployment/kyverno-authz-server -n kyverno
```

#### Issue: High latency on requests

**Symptoms**: Requests take several seconds with authorization enabled.

**Diagnosis**:
```bash
# Check Kyverno server metrics
kubectl port-forward -n kyverno svc/kyverno-authz-server 8080:8080
curl http://localhost:8080/metrics | grep authz_request_duration
```

**Common causes**:
1. **JWKS fetching on every request**: No caching of certificates
2. **Resource limits**: Kyverno server CPU-throttled
3. **Network latency**: JWKS endpoint is remote

**Solution**:
```yaml
# Kyverno caches JWKS by default, but ensure it's enabled
# Add resource limits to prevent throttling
resources:
  requests:
    cpu: "500m"
    memory: "512Mi"
  limits:
    cpu: "1000m"
    memory: "1Gi"
```

### Frequently Asked Questions

**Q: Can I use this with AWS Cognito or other IdPs?**

A: Yes! Just update the `jwks_url` variable in your ValidatingPolicy to point to your IdP's JWKS endpoint. Any OIDC-compliant provider works (Cognito, Auth0, Azure AD, Okta, etc.).

**Q: How do I handle token refresh?**

A: Token refresh is handled client-side. Your application should:
1. Detect 401 responses
2. Use the refresh token to get a new access token from the IdP
3. Retry the request with the new token

Kyverno only validates access tokens; refresh logic stays in your app or API gateway.

**Q: Does this work with Istio Ambient mode?**

A: Kyverno Authorization Server is designed to work with Istio's external authorization filter, which is supported in both sidecar and ambient (ztunnel) modes. Testing with ambient mode is recommended for your specific Istio version.

**Q: What happens if Kyverno Authorization Server is down?**

A: By default, the `failurePolicy: Fail` means requests will be denied if Kyverno is unreachable. For high availability:
- Run multiple replicas of Kyverno Authorization Server
- Configure a PodDisruptionBudget
- Monitor Kyverno health and set up alerts

Alternatively, set `failurePolicy: Allow` to fail open (not recommended for production).

**Q: Can I have different policies for different services?**

A: Yes! Create separate ValidatingPolicies in each namespace or use a single cluster-wide policy with conditional logic based on `object.attributes.destination.namespace` or `object.attributes.destination.name`.

**Q: How do I test policies before deploying?**

A: Use `kubectl apply --dry-run=server` to validate syntax. For functional testing:
1. Deploy to a test namespace first
2. Use Istio traffic shifting to gradually route traffic
3. Monitor authorization deny rates

**Q: What's the performance impact?**

A: Expect ~10-50ms additional latency per request for JWT validation. The impact is lower than per-pod OPA sidecars because:
- Single shared evaluator with warm caches
- Optimized gRPC communication
- No bundle parsing per request

Benchmark your specific workload to measure impact.

**Q: Can I use this without Istio?**

A: Kyverno Authorization Server supports any Envoy-based proxy, including:
- Envoy Gateway
- Contour
- Ambassador
- Standalone Envoy

You'll need to configure Envoy's `ext_authz` filter to point to Kyverno.

## Conclusion

Centralized authorization with Kyverno and Istio fundamentally transforms how you secure Kubernetes workloads. By eliminating per-pod OPA sidecars, you reduce operational complexity, cut cloud costs by ~30%, and gain immediate policy consistency across your entire mesh. The architecture we've built here—JWT validation via JWKS, claim-based authorization, and fine-grained access control—applies to both north-south ingress traffic and east-west service communication without requiring application code changes.

The business impact is clear: **lower infrastructure spend**, **faster policy rollouts**, **simplified compliance**, and **reduced operational burden**. Whether you're securing a handful of microservices or hundreds, this centralized approach scales effortlessly while preserving your existing identity infrastructure investments.

Ready to implement this in your environment? Start with a single namespace or service group to validate performance and policy coverage. Integrate with your existing IdP (AWS Cognito, Azure AD, Okta), manage policies via GitOps, and measure the resource savings. As confidence grows, expand incrementally, retiring sidecars and enjoying the operational simplicity of centralized authorization.

**Next steps**:
- **Explore the code**: The complete example is available at [your-repository-link]
- **Read more about Kyverno**: [kyverno.io/docs](https://kyverno.io/docs/)
- **Learn Istio security**: [istio.io/docs/concepts/security](https://istio.io/latest/docs/concepts/security/)
- **Platform engineering best practices**: Explore how policy-as-code accelerates DevSecOps workflows at scale

The future of Kubernetes authorization is centralized, declarative, and mesh-native. Start building it today.

---

**Keywords**: Policy as code, DevSecOps, Platform Engineering, Kubernetes security, Service mesh, JWT validation, Istio authorization, Kyverno, Zero Trust, API security, Shift-left security, Cloud native security

