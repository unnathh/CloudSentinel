<div align="center">

# ☁️ CloudSentinel

### Enterprise-Grade AWS Cloud Security Posture Management (CSPM)

Discover cloud misconfigurations, detect IAM privilege escalation paths, evaluate CIS AWS Foundations Benchmark compliance, and visualize attack paths through an interactive security dashboard.

<br>

<img src="docs/images/dashboard.png" alt="CloudSentinel Dashboard" width="100%"/>

<br>

![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-009688?logo=fastapi&logoColor=white)
![React](https://img.shields.io/badge/React-61DAFB?logo=react&logoColor=black)
![TypeScript](https://img.shields.io/badge/TypeScript-3178C6?logo=typescript&logoColor=white)
![AWS](https://img.shields.io/badge/AWS-Security-FF9900?logo=amazonaws&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-4169E1?logo=postgresql&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-2496ED?logo=docker&logoColor=white)

</div>

---

# Overview

CloudSentinel is an enterprise-inspired Cloud Security Posture Management (CSPM) platform built for AWS environments.

It continuously analyzes cloud infrastructure, detects security misconfigurations, evaluates CIS AWS Foundations Benchmark compliance, discovers IAM privilege escalation paths, and provides actionable remediation guidance through an intuitive security dashboard.

Designed as a portfolio-quality security engineering project, CloudSentinel combines cloud security, graph analysis, backend engineering, and modern web technologies into a single platform.

---

# Key Features

### Cloud Configuration Assessment

- AWS resource inventory
- IAM analysis
- S3 security analysis
- EC2 inspection
- Security Group auditing
- CloudTrail validation
- KMS configuration checks
- Lambda security analysis
- RDS inspection
- VPC configuration review

---

### CIS AWS Foundations Benchmark

Evaluate AWS accounts against industry-standard CIS benchmarks.

Examples include:

- Root account MFA
- Root access keys
- Password policies
- Public S3 buckets
- Bucket encryption
- Bucket logging
- Security Groups open to Internet
- CloudTrail enabled
- KMS rotation
- IAM wildcard permissions

---

### IAM Privilege Escalation Detection

Analyze IAM permissions and discover potential privilege escalation chains.

Example attack path:

```
Developer User
        │
iam:PassRole
        │
EC2 Instance
        │
Administrator Role
        │
AdministratorAccess
```

Powered by NetworkX graph analysis.

---

### Interactive Attack Graph

Visualize cloud attack paths using Cytoscape.js.

Features:

- Interactive graph
- Zoom & pan
- Risk highlighting
- Node inspection
- Attack chain visualization
- Permission relationships

---

### Security Dashboard

Monitor cloud posture through a modern dashboard.

Includes:

- Total Resources
- Findings by Severity
- Compliance Score
- Risk Score
- MITRE ATT&CK Mapping
- Scan History
- Findings Timeline

---

### Reports

Export findings as:

- PDF
- CSV
- JSON

---

### Demo Mode

CloudSentinel includes a built-in demo environment.

No AWS account is required.

The demo generates:

- IAM users
- Roles
- Policies
- EC2 instances
- Security Groups
- Public S3 buckets
- Attack paths
- Security findings

making it easy to explore the platform without cloud credentials.

---

# Architecture

```
                    AWS Account
                          │
                   Read-only IAM
                          │
                       boto3
                          │
                 Resource Collectors
                          │
        ┌─────────────────┴─────────────────┐
        │                                   │
  CIS Rule Engine                 IAM Analyzer
        │                                   │
        └──────────────┬────────────────────┘
                       │
          Privilege Escalation Graph
                       │
                 NetworkX Engine
                       │
                  PostgreSQL
                       │
                   FastAPI API
                       │
                React Dashboard
```

---

# Tech Stack

| Category | Technology |
|-----------|------------|
| Backend | FastAPI |
| Language | Python 3.12 |
| Frontend | React + TypeScript |
| Styling | Tailwind CSS |
| Database | PostgreSQL |
| ORM | SQLAlchemy |
| Cloud SDK | boto3 |
| Graph Engine | NetworkX |
| Graph Visualization | Cytoscape.js |
| Charts | Recharts |
| Authentication | JWT |
| Deployment | Docker + Railway |

---

# Project Structure

```
CloudSentinel/

backend/
frontend/
docs/
docker/

README.md
LICENSE
```

---

# Screenshots

## Dashboard

<img src="docs/images/dashboard.png"/>

---

## Findings

<img src="docs/images/findings.png"/>

---

## Attack Graph

<img src="docs/images/attack-graph.png"/>

---

## IAM Analyzer

<img src="docs/images/iam.png"/>

---

# Detection Capabilities

✔ Public S3 Buckets

✔ Wildcard IAM Policies

✔ Public Security Groups

✔ Root MFA Disabled

✔ CloudTrail Disabled

✔ Weak Password Policies

✔ Unencrypted Resources

✔ Excessive IAM Permissions

✔ Privilege Escalation Paths

✔ Misconfigured Security Groups

✔ KMS Rotation Disabled

✔ Public RDS Instances

---

# MITRE ATT&CK Mapping

CloudSentinel maps security findings to MITRE ATT&CK Cloud techniques.

Examples:

| Finding | Technique |
|----------|-----------|
| Privilege Escalation | TA0004 |
| Valid Accounts | T1078 |
| Cloud Storage Discovery | T1619 |
| Account Discovery | T1087 |

---

# Security Workflow

```
Connect AWS Account

↓

Collect Resources

↓

Analyze Configuration

↓

Run CIS Checks

↓

Analyze IAM

↓

Generate Attack Graph

↓

Calculate Risk

↓

Display Dashboard

↓

Export Reports
```

---

# Getting Started

## Clone Repository

```bash
git clone https://github.com/yourusername/CloudSentinel.git

cd CloudSentinel
```

---

## Backend

```bash
cd backend

pip install -r requirements.txt

uvicorn app.main:app --reload
```

---

## Frontend

```bash
cd frontend

npm install

npm run dev
```

---

# Roadmap

- AWS Support
- Azure CSPM
- GCP CSPM
- Kubernetes Security
- Terraform Scanner
- AWS Config Integration
- Security Hub Integration
- Multi-account Management
- Scheduled Scans
- Slack Notifications

---

# Contributing

Contributions, suggestions, and feature requests are welcome.

Feel free to open an issue or submit a pull request.

---

# License

Licensed under the MIT License.

---

<div align="center">

Built with ❤️ for Cloud Security Engineers

</div>
