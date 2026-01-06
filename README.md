# 🏢 Customer Complaint Management System (CCMS)

## 📌 Project Overview
A robust, full-stack web application designed to digitize and streamline the complaint resolution process. This system replaces manual tracking with a centralized digital dashboard, allowing users to file complaints and administrators to track and resolve them efficiently.

## 🎯 Objectives
- **Digitization:** Move from email/paper complaints to a structured database system.
- **Transparency:** Users can track the real-time status of their complaints (Pending → Resolved).
- **Efficiency:** Admins have a centralized panel to manage all issues.

## 🚀 Current Features (Completed)
- **Secure Authentication:** User Registration & Login system with password hashing (Security Best Practices).
- **Role-Based Access Control (RBAC):** Distinct logic for 'Customers' and 'Admins'.
- **Database Management:** Efficient storage using SQLite & SQLAlchemy with One-to-Many relationships.
- **Complaint Filing:** Users can file complaints with categories (Electrical, WiFi, etc.).
- **User Dashboard:** Customers can view the real-time status and history of their complaints.

## 🛠 Tech Stack
- **Backend:** Python (Flask Microframework)
- **Database:** SQLite (Relational DB)
- **Frontend:** HTML5, CSS3, Bootstrap 5
- **Tools:** VS Code, Git, GitHub

## 📂 System Architecture
1. **User** logs in and submits a complaint form.
2. **Backend** validates data and stores it in the **Database**.
3. **Database** links the complaint to the specific User ID.
4. **User Dashboard** fetches and displays the complaint history dynamically.

## 📌 Next Steps
- Build Admin Dashboard (to solve complaints).
- Add status updates (Pending → Resolved).