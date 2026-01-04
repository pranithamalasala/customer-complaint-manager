# 🏢 Customer Complaint Management System (CCMS)

## 📌 Project Overview
A robust, full-stack web application designed to digitize and streamline the complaint resolution process. This system replaces manual tracking with a centralized digital dashboard, allowing users to file complaints and administrators to track and resolve them efficiently.

## 🎯 Objectives
- **Digitization:** Move from email/paper complaints to a structured database system.
- **Transparency:** Users can track the real-time status of their complaints (Pending → Resolved).
- **Efficiency:** Admins have a centralized panel to manage all issues.

## 🚀 Key Features
- **Secure Authentication:** User Registration & Login system with password hashing (Security Best Practices).
- **Role-Based Access Control (RBAC):** Distinct dashboards for 'Customers' and 'Admins'.
- **Complaint Tracking:** Live status updates and history logs.
- **Database Management:** Efficient storage and retrieval using SQLite & SQLAlchemy.
- **Responsive UI:** Clean interface built with Bootstrap 5.

## 🛠 Tech Stack
- **Backend:** Python (Flask Microframework)
- **Database:** SQLite (Relational DB)
- **Frontend:** HTML5, CSS3, Bootstrap
- **Tools:** VS Code, Git, GitHub

## 📂 System Architecture
1. **User** logs in and submits a complaint form.
2. **Backend** validates data and stores it in the **Database**.
3. **Admin** logs in to view pending tickets.
4. **Admin** updates the status (e.g., "Resolved").
5. **Database** updates the user's view instantly.
