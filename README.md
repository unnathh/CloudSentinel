# 🛡️ CloudSentinel

<div align="center">

### Cloud Security Posture Management (CSPM) Platform

**Secure • Audit • Analyze • Visualize**

Automate AWS security assessments, monitor cloud posture, detect misconfigurations, analyze IAM permissions, and visualize cloud infrastructure from a single dashboard.

<br>

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge\&logo=python\&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=for-the-badge\&logo=fastapi\&logoColor=white)
![React](https://img.shields.io/badge/React-20232A?style=for-the-badge\&logo=react)
![TypeScript](https://img.shields.io/badge/TypeScript-3178C6?style=for-the-badge\&logo=typescript)
![Docker](https://img.shields.io/badge/Docker-2496ED?style=for-the-badge\&logo=docker\&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-success?style=for-the-badge)

</div>

---

# 📖 Table of Contents

* Overview
* Features
* Demo
* Screenshots
* Architecture
* Tech Stack
* Project Structure
* Installation
* API
* Roadmap
* Contributing
* License

---

# 🚀 Overview

CloudSentinel is a modern **Cloud Security Posture Management (CSPM)** platform built to simplify cloud security monitoring and compliance.

It continuously evaluates AWS resources, detects security risks, performs compliance checks, analyzes IAM permissions, and presents findings through a clean and interactive dashboard.

Whether you're a cloud engineer, security analyst, or student learning cloud security, CloudSentinel provides an easy way to understand the security posture of AWS environments.

---

# 🎯 Key Highlights

* ✅ AWS Security Auditing
* ✅ CIS AWS Foundations Benchmark Checks
* ✅ IAM Permission Analysis
* ✅ Security Dashboard
* ✅ Interactive Graph Visualization
* ✅ Report Generation
* ✅ Docker Deployment
* ✅ REST API
* ✅ Modern React Interface

---

# 🎥 Demo

> 📹 **Demo Video**
>
> *(Add YouTube or Loom link here)*

```
https://your-demo-link.com
```

---

# 🖼️ Screenshots

## 🔐 Login

> Add screenshot here

```text
docs/login.png
```

---

## 📊 Dashboard

> Add screenshot here

```text
docs/dashboard.png
```

---

## ☁️ AWS Security Scan

> Add screenshot here

```text
docs/aws-scan.png
```

---

## 🕸️ Security Graph

> Add screenshot here

```text
docs/security-graph.png
```

---

## 📄 Security Report

> Add screenshot here

```text
docs/report.png
```

---

# ⚙️ How It Works

```text
                 User
                   │
                   ▼
         React + TypeScript UI
                   │
             REST API Calls
                   │
                   ▼
          FastAPI Backend Server
                   │
        ┌──────────┴──────────┐
        │                     │
        ▼                     ▼
 AWS Security Scanner     Database
        │
        ▼
 IAM Analysis
 CIS Benchmarks
 Security Findings
        │
        ▼
 Dashboard & Reports
```

---

# 🛠️ Tech Stack

| Category      | Technologies                          |
| ------------- | ------------------------------------- |
| Frontend      | React, TypeScript, Vite, Tailwind CSS |
| Backend       | FastAPI, Python, SQLAlchemy           |
| Database      | SQLite                                |
| Visualization | Cytoscape.js                          |
| DevOps        | Docker, Docker Compose                |

---

# 📂 Project Structure

```text
CloudSentinel
│
├── backend/
│   ├── api/
│   ├── models/
│   ├── services/
│   └── tests/
│
├── frontend/
│   ├── src/
│   ├── assets/
│   └── components/
│
├── docs/
│
├── docker-compose.yml
├── README.md
└── LICENSE
```

---

# 🚀 Installation

## Clone Repository

```bash
git clone https://github.com/unnathh/cloudsentinel.git

cd cloudsentinel
```

---

## Run with Docker

```bash
docker compose up --build
```

Open your browser:

```
http://localhost
```

---

# 📡 API Overview

| Endpoint   | Description         |
| ---------- | ------------------- |
| /login     | User Authentication |
| /scan      | Start Security Scan |
| /dashboard | Dashboard Data      |
| /reports   | Security Reports    |
| /graph     | Security Graph      |

---

# 📊 Current Status

| Feature          | Status    |
| ---------------- | --------- |
| Backend          | ✅ Stable  |
| Frontend         | ✅ Stable  |
| Docker           | ✅ Ready   |
| Tests            | ✅ Passing |
| Production Build | ✅ Working |

---

# 🛣️ Roadmap

### Version 1.0

* AWS Security Scanner
* IAM Analysis
* Dashboard
* Reports

### Version 2.0

* Azure Support
* GCP Support
* AI Risk Scoring

### Version 3.0

* Kubernetes Security
* Continuous Monitoring
* Auto Remediation

---

# 🤝 Contributing

Contributions are welcome.

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push your branch
5. Open a Pull Request

---

# 📜 License

Licensed under the MIT License.

---

# 👨‍💻 Author

**UNNATH**

GitHub: https://github.com/unnathh

---

<div align="center">

### ⭐ If you like this project, consider giving it a star!

Made with using **FastAPI**, **React**, **Docker**, and modern cloud security engineering.

</div>
