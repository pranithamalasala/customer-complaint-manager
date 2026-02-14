

🏢 AI-Based Customer Complaint Management System (CCMS)
🌐 Live Demo

Deployed on Render:
https://customer-complaint-manager.onrender.com
Admin Login (For Evaluation):

Username: admin@infomatic.com
Password: admin123
## 📸 Screenshots

### 🔐 Login Page
<img width="1884" height="849" alt="image" src="https://github.com/user-attachments/assets/41430041-bfdf-4c9f-8527-31db5e1ba180" />


### 📊 Admin Dashboard
<img width="1909" height="855" alt="image" src="https://github.com/user-attachments/assets/7bf79649-2aaf-4e1b-9f8e-358f859a4610" />


### 📝 File Complaint Page
<img width="1380" height="812" alt="image" src="https://github.com/user-attachments/assets/11c5f924-4635-4fb6-a202-d7be985bede8" />



📌 Project Overview

This is a full-stack web application designed to help organizations manage customer support tickets efficiently. Traditionally, complaints were handled manually through emails, which was slow and unstructured.

This system provides a centralized dashboard where employees can submit complaints, and administrators can monitor, prioritize, and resolve them efficiently.

What makes this project unique is the integration of Artificial Intelligence. Instead of relying only on user input, the system automatically analyzes the complaint text and predicts both:

🔴 Priority Level

🏷 Category Type

🎯 Objectives

Organization: Replace manual email handling with a structured database system.

Automation: Use AI to automatically detect urgent issues.

Security: Restrict access to authorized company employees only.

Transparency: Allow users to track the status of their complaints in real-time.

🚀 Key Features
🤖 1. AI & Automation

Auto-Priority Detection: Machine learning model detects critical keywords like "fire", "server crash", or "system failure" and automatically marks the complaint as High Priority.

Smart Categorization: AI predicts whether the issue belongs to Hardware, Software, or Network categories.

🔐 2. Security

Company Access Code: Registration requires a secret code (INFO-2026).

Domain Restriction: Only corporate emails (@infomatic.com) are allowed to register.

Role-Based Access: Separate dashboards for Admin and Employees.

📊 3. Admin Dashboard

Complaint statistics (Pending vs Resolved).

High-priority ticket alerts.

Search functionality for quick filtering.

CSV export of complaint reports.

Screenshot uploads for issue evidence.

💬 4. Communication System

Each ticket includes a comment section where Admin and User can communicate directly to resolve issues faster.
## 📁 Project Structure

app.py
requirements.txt
templates/
static/
model.pkl


🛠 Tech Stack

Backend:

Python

Flask

SQLAlchemy

Frontend:

HTML

CSS

Bootstrap 5

Database:

PostgreSQL (Production - Render)

SQLite (Local Development)

AI & Data Science:

Scikit-learn

Pandas

Pickle

Deployment:

Render (Cloud Hosting)

Gunicorn (WSGI Server)
## ⚙️ Local Setup Instructions

1. Clone the repository:
   git clone https://github.com/pranithamalasala/customer-complaint-manager.git

2. Navigate into the folder:
   cd customer-complaint-manager

3. Create a virtual environment (recommended):
   python -m venv venv
   source venv/bin/activate   # On Windows use: venv\Scripts\activate

4. Install dependencies:
   pip install -r requirements.txt

5. Run the application:
   python app.py

6. Open in browser:
   http://127.0.0.1:5000



📂 System Workflow

User Login: Employee logs in using company email.

Complaint Submission: User describes issue and optionally uploads an image.

AI Analysis: Machine learning model predicts priority and category.

Admin Action: Admin reviews ticket, communicates, and marks it resolved.

Status Tracking: User can monitor progress in dashboard.

📈 Project Status

✅ Fully deployed and functional
✅ Production database integrated
✅ AI prediction working
✅ Role-based authentication implemented
✅ Cloud hosting configured
## 🚀 Future Improvements

- Email notifications for high-priority tickets
- JWT-based authentication
- Docker containerization
- Cloud storage for uploaded files
- CI/CD integration
