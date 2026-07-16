<<<<<<< HEAD
# CloudSentinel – Enterprise-Grade AWS Cloud Security Posture Management (CSPM) Platform

CloudSentinel is an original, production-quality Cloud Security Posture Management (CSPM) platform modeled after top-tier enterprise cloud security products. The application connects to AWS using **read-only credentials**, inventories cloud configurations, runs CIS Foundations Benchmark checks, maps findings to MITRE ATT&CK techniques, and builds a directed IAM relationship graph utilizing NetworkX to locate and highlight privilege escalation attack paths.

---

## Technical Stack

* **Backend**: Python 3.12, FastAPI, SQLAlchemy 2.0 (async), NetworkX, PyJWT, Bcrypt, Boto3, Pytest.
* **Frontend**: React, TypeScript, Vite, Tailwind CSS, Recharts (charts), Cytoscape.js (visual graph), Lucide Icons, Framer Motion.
* **Database**: SQLite (local development / testing), PostgreSQL-ready.
* **DevOps**: Docker, Docker Compose, Nginx.

---

## Features

1. **AWS Scans (Real & Demo)**: Secure connection validation. Supports a fully featured **Demo Mode** (`demo-aws-account`) generating a pre-populated vulnerable sandbox layout (wildcard policies, open ports, missing encryption, unencrypted databases, public APIs, and complex IAM paths).
2. **CIS AWS Foundations Benchmark**: Out-of-the-box evaluations for Root MFA, password policy strength, public S3 buckets, exposed ports (22, 3389, 80), logging configuration, KMS rotation, and RDS accessibility.
3. **Privilege Escalation Solver**: Custom parser that resolves Allow/Deny policies and trust structures to construct a directed permission graph using **NetworkX**. It calculates shortest-path compromise scenarios (e.g. standard IAM user to full AdministratorAccess) and maps exploit narratives.
4. **Interactive Attack Graph**: Rendered using **Cytoscape.js** with vibrant cybersecurity styling, allowing zoom/pan, node metadata inspection, and visual highlighted attack paths.
5. **Mitre ATT&CK Integration**: Auto-maps findings to Technique IDs (e.g. T1530: Cloud Storage Discovery, T1078: Valid Accounts, T1556: Modify Authentication Process).
6. **Remediation Snippets**: Outlines step-by-step mitigation advice and provides copyable **AWS CLI** commands and **Terraform HCL** blocks for immediate code remediation.
7. **Multi-Format Export**: Generates and downloads scan report summaries in JSON, CSV, and formatted PDF sheets (leveraging ReportLab).

---

## Project Structure

```text
cloudsentinel/
├── backend/
│   ├── app/
│   │   ├── api/          # FastAPI routes (auth, accounts, findings, graph, resources, reports)
│   │   ├── collectors/   # AWS SDK collectors & Mock generator
│   │   ├── analyzers/    # NetworkX privilege graph builder & IAM parser
│   │   ├── rules/        # CIS benchmark rules registry and definitions
│   │   ├── models/       # SQLAlchemy database models
│   │   ├── schemas/      # Pydantic validation schemas
│   │   ├── services/     # Auth token and credentials encryption helpers
│   │   ├── config.py     # Application environment configurations
│   │   ├── database.py   # DB sessions and engine hooks
│   │   └── main.py       # FastAPI application entrypoint
│   ├── tests/            # pytest unit & integration suites
│   ├── Dockerfile
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   ├── contexts/     # Auth and AWS Account React Contexts
│   │   ├── layouts/      # Dashboard master layout grids
│   │   ├── pages/        # Dashboard view screens (Dashboard, Findings, Graph, Accounts, Resources)
│   │   ├── services/     # Axios client mappings to backend API
│   │   ├── types/        # TypeScript interfaces
│   │   ├── App.tsx       # Main router setup and guards
│   │   └── index.css     # CSS scrollbars and tailwind tokens
│   ├── Dockerfile
│   ├── tailwind.config.js
│   ├── tsconfig.json
│   └── vite.config.ts
├── docker-compose.yml
└── README.md
=======
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
>>>>>>> 95944c98e277f7060215efae3dc83f84419375c6
```

---

<<<<<<< HEAD
## AWS IAM Security Best Practice (Read-Only)

CloudSentinel operates entirely on read-only API calls. Under no circumstance should AdministratorAccess keys be linked.
A sample IAM policy template for connection:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "iam:List*",
                "iam:Get*",
                "s3:ListAllMyBuckets",
                "s3:GetBucketLocation",
                "s3:GetBucketPublicAccessBlock",
                "s3:GetBucketPolicy",
                "s3:GetBucketEncryption",
                "s3:GetBucketLogging",
                "s3:GetBucketVersioning",
                "s3:GetBucketAcl",
                "ec2:DescribeInstances",
                "ec2:DescribeSecurityGroups",
                "ec2:DescribeVolumes",
                "ec2:DescribeVpcs",
                "cloudtrail:DescribeTrails",
                "cloudtrail:GetTrailStatus",
                "kms:ListKeys",
                "kms:DescribeKey",
                "kms:GetKeyRotationStatus",
                "lambda:ListFunctions",
                "lambda:ListFunctionUrlConfigs",
                "rds:DescribeDBInstances"
            ],
            "Resource": "*"
        }
    ]
}
=======
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
>>>>>>> 95944c98e277f7060215efae3dc83f84419375c6
```

---

<<<<<<< HEAD
## Getting Started

### Option 1: Docker Compose (Recommended)

1. Launch both containers (FastAPI on port 8000 and React on port 80):
   ```bash
   docker-compose up --build -d
   ```
2. Open your browser and navigate to `http://localhost`.

### Option 2: Local Installation

#### 1. Backend Setup
1. Navigate to the backend directory:
   ```bash
   cd backend
   ```
2. Create and activate a Python virtual environment:
   ```bash
   python -m venv venv
   # On Windows:
   .\venv\Scripts\activate
   # On macOS/Linux:
   source venv/bin/activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Launch the FastAPI server:
   ```bash
   uvicorn app.main:app --reload --port 8000
   ```
5. API interactive docs will be available at `http://localhost:8000/docs`.

#### 2. Frontend Setup
1. Navigate to the frontend directory:
   ```bash
   cd ../frontend
   ```
2. Install npm dependencies:
   ```bash
   npm install
   ```
3. Launch the Vite development server:
   ```bash
   npm run dev
   ```
4. Access the web interface at `http://localhost:5173`.

---

## Seed Accounts (Credentials)

During backend startup, the database is automatically populated with these user accounts to facilitate local testing:

| Role | Email Identity | Password |
|---|---|---|
| **Administrator** | `admin@cloudsentinel.local` | `adminpassword` |
| **Security Analyst** | `analyst@cloudsentinel.local` | `analystpassword` |
| **Viewer** | `viewer@cloudsentinel.local` | `viewerpassword` |

*To run tests without active AWS credentials, choose the pre-linked account `demo-aws-account` from the top selector and click **Scan**.*

---

## Privilege Escalation Algorithm Design

CloudSentinel models IAM relationships as a Directed Graph:
* **Nodes**: Security Principals (Users, Roles), policies, and resources (EC2, Lambda).
* **Edges**: Directed relationships representing permissions.
  * Direct transitions: `sts:AssumeRole` (allowances/trust policies), `EC2 Instance Profile` bindings.
  * Privilege Escalation transitions: Added dynamically when an entity possesses actions like `iam:PassRole` and `ec2:RunInstances` on `*` resources.
* **Path Finding**: Uses **NetworkX** to perform shortest-path analysis from entry-point nodes (non-administrative IAM users) to targets (identities possessing AdministratorAccess or mapped to the admin role).
=======
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
>>>>>>> 95944c98e277f7060215efae3dc83f84419375c6
