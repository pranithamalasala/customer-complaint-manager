<div align="center">

# 🏢 AI-Based Customer Complaint Management System

### *Smart Ticketing. Automated Priority. Zero Email Chaos.*

**A full-stack web app that uses Machine Learning to auto-categorize and prioritize customer complaints — built for organized, efficient support management.**

[![Live Demo](https://img.shields.io/badge/🚀_Live_Demo-Render-46E3B7?style=for-the-badge)](https://customer-complaint-manager.onrender.com)
[![GitHub Repo](https://img.shields.io/badge/GitHub-customer--complaint--manager-181717?style=for-the-badge&logo=github)](https://github.com/pranithamalasala/customer-complaint-manager)
[![Python](https://img.shields.io/badge/Python-Flask-3776AB?style=for-the-badge&logo=python&logoColor=white)]()
[![AI Powered](https://img.shields.io/badge/AI-Scikit--learn-F7931E?style=for-the-badge&logo=scikitlearn&logoColor=white)]()
[![PostgreSQL](https://img.shields.io/badge/Database-PostgreSQL-336791?style=for-the-badge&logo=postgresql&logoColor=white)]()

</div>

---

## 🔐 Demo Login

| Role | Email | Password |
|------|-------|----------|
| **Admin** | `admin@infomatic.com` | `admin123` |

> Registration requires company email `@infomatic.com` + access code `INFO-2026`

---

## 📸 Screenshots

| Login Page | Admin Dashboard | File Complaint |
|:----------:|:---------------:|:--------------:|
| ![Login](./static/screenshots/login.png) | ![Dashboard](./static/screenshots/dashboard.png) | ![Complaint](./static/screenshots/complaint.png) |

---

## 📌 What is CCMS?

Traditional complaint handling via emails is slow, unstructured, and hard to track. CCMS replaces that with a **centralized dashboard** where:

- Employees submit complaints through a structured form
- **AI automatically predicts priority level and category**
- Admins monitor, communicate, and resolve tickets efficiently
- Users track their complaint status in real-time

---

## ✨ Features

### 🤖 AI & Automation
- **Auto-Priority Detection** — ML model flags keywords like *"fire"*, *"server crash"*, *"system failure"* as High Priority automatically
- **Smart Categorization** — Predicts whether the issue is Hardware, Software, or Network

### 🔐 Security
- **Access Code Registration** — Only employees with code `INFO-2026` can register
- **Domain Restriction** — Only `@infomatic.com` emails allowed
- **Role-Based Access** — Separate dashboards for Admin and Employees

### 📊 Admin Dashboard
- Complaint statistics (Pending vs Resolved)
- High-priority ticket alerts
- Search & filter functionality
- CSV export of complaint reports
- Screenshot uploads for issue evidence

### 💬 Communication
- Per-ticket comment threads for Admin ↔ User communication

---

## 🛠 Tech Stack

| Layer | Technology |
|-------|-----------|
| **Backend** | Python, Flask, SQLAlchemy |
| **Frontend** | HTML, CSS, Bootstrap 5 |
| **Database** | PostgreSQL (Production), SQLite (Local) |
| **AI / ML** | Scikit-learn, Pandas, Pickle |
| **Deployment** | Render, Gunicorn |

---

## 🚀 Quick Start

### 1. Clone the repo
```bash
git clone https://github.com/pranithamalasala/customer-complaint-manager.git
cd customer-complaint-manager
```

### 2. Create virtual environment
```bash
python -m venv venv
source venv/bin/activate       # Mac/Linux
venv\Scripts\activate          # Windows
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Run the app
```bash
python app.py
```

> Open **http://127.0.0.1:5000** in your browser

---

## 📂 How It Works

```
Employee Login (company email required)
        ↓
Submit Complaint (text + optional image)
        ↓
AI Model analyzes complaint text
        ↓
Auto-assigns Priority (High/Medium/Low) + Category (Hardware/Software/Network)
        ↓
Admin reviews ticket on dashboard
        ↓
Admin & User communicate via comments
        ↓
Admin marks ticket Resolved
        ↓
User tracks status in real-time
```

---

## 📁 Project Structure

```
customer-complaint-manager/
├── app.py                  # Main Flask application
├── models.py               # Database models
├── train_model.py          # ML model training
├── model.pkl               # Trained ML model
├── complaints_dataset.csv  # Training dataset
├── create_dataset.py       # Dataset generator
├── setup_db.py             # Database setup
├── requirements.txt
├── runtime.txt
├── templates/              # HTML templates
└── static/                 # CSS, JS, images
```

---

## 📈 Project Status

- ✅ Fully deployed and functional
- ✅ Production PostgreSQL database integrated
- ✅ AI prediction working
- ✅ Role-based authentication implemented
- ✅ Cloud hosting on Render configured

---

## 🗺 Roadmap

- [ ] Email notifications for high-priority tickets
- [ ] JWT-based authentication
- [ ] Docker containerization
- [ ] Cloud storage for uploaded files (AWS S3)
- [ ] CI/CD pipeline integration

---

## 👩‍💻 Contributors

<table>
  <tr>
    <td align="center">
      <a href="https://github.com/pranithamalasala">
        <b>Pranitha</b><br/>
        <sub>Developer</sub>
      </a>
    </td>
  </tr>
</table>

---

## 📄 License

This project is open-source and available under the [MIT License](LICENSE).

---

<div align="center">

**Built with ❤️ to eliminate complaint chaos and bring AI-powered efficiency to support teams**

⭐ Star this repo if you found it useful!

[![Stars](https://img.shields.io/github/stars/pranithamalasala/customer-complaint-manager?style=social)](https://github.com/pranithamalasala/customer-complaint-manager)

</div>
