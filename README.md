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


---

# 🖼️ Screenshots

## 🔐 Login

<img width="1915" height="957" alt="image" src="https://github.com/user-attachments/assets/c9ea27da-d367-4253-ad99-d8c2ad7f340c" />


---

## 📊 Dashboard

> <img width="1907" height="962" alt="image" src="https://github.com/user-attachments/assets/e5f9eb2f-9a24-44b8-8723-73ba1550792c" />


---

## ☁️ AWS Security Scan

> <img width="1905" height="950" alt="image" src="https://github.com/user-attachments/assets/c35e1189-a9fd-4e0c-bac1-9229bb13347b" />


---

## 🕸️ Security Graph

> <img width="1912" height="960" alt="image" src="https://github.com/user-attachments/assets/4d5f58fb-f10e-43f4-957a-9aef92439210" />


---

## 📄 Security Report

> <img width="1475" height="897" alt="image" src="https://github.com/user-attachments/assets/0906342b-2c66-4680-a4fc-5c4d40a17097" />


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
