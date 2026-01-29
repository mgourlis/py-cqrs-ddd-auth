# py-cqrs-ddd-auth

A **toolkit-native** authentication and authorization library built using CQRS, DDD, and Saga patterns.

---

## Key Features

- **Domain-Driven Authentication**: Proper Aggregates, Commands, and Events for authentication flows
- **Pluggable Identity Providers**: Infrastructure adapters for Keycloak, OAuth2, and custom IdPs
- **ABAC Integration**: Authorization as a query leveraging the Stateful ABAC Policy Engine
- **2FA as a Saga**: Multi-step authentication flows with OTP support
- **Framework Adapters**: Thin bridges for FastAPI and Django

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Authentication Domain                        │
├─────────────────────────────────────────────────────────────────┤
│  Aggregates:         Value Objects:        Domain Events:       │
│  • AuthSession       • Credentials         • AuthSessionCreated │
│  • OTPChallenge      • OTPCode             • OTPRequired        │
│  • TokenPair         • UserClaims          • AuthSucceeded      │
└─────────────────────────────────────────────────────────────────┘
```

---

## Installation

```bash
# Core library
pip install py-cqrs-ddd-auth

# With Keycloak adapter
pip install py-cqrs-ddd-auth[keycloak]

# With FastAPI integration
pip install py-cqrs-ddd-auth[fastapi]

# Everything
pip install py-cqrs-ddd-auth[all]
```

---

## Quick Start

```python
from cqrs_ddd_auth.application.commands import AuthenticateWithCredentials
from cqrs_ddd_auth.adapters.keycloak import KeycloakIdentityProvider

# Configure identity provider
idp = KeycloakIdentityProvider(
    server_url="https://keycloak.example.com",
    realm="my-realm",
    client_id="my-client",
    client_secret="secret"
)

# Authenticate
result = await mediator.send(AuthenticateWithCredentials(
    username="user@example.com",
    password="password123"
))
```

---

## License

MIT License - see [LICENSE](LICENSE) for details.
