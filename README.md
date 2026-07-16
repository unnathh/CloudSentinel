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
```

---

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
```

---

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
