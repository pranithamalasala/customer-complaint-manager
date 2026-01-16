Here is the updated README.md. I have rewritten it to sound natural and grounded—like a developer explaining their work, rather than a marketing brochure.

🏢 Customer Complaint Management System (CCMS) with AI
📌 Project Overview
This is a full-stack web application designed to help companies manage customer support tickets efficiently. Before this system, complaints were handled manually via email, which was messy and slow. This project solves that problem by creating a central dashboard where users can file complaints and admins can track them from start to finish.

What makes this project unique is that I integrated Artificial Intelligence. Instead of relying on users to tell us if a problem is urgent, the system reads their complaint and decides the priority automatically.

🎯 Objectives
Organization: Move away from messy emails to a structured database.

Automation: Use AI to detect urgent issues (like "Fire" or "Server Crash") instantly.

Security: Ensure only actual employees can access the internal dashboard.

Transparency: Let users see exactly when their issue is fixed.

🚀 Key Features
1. AI & Automation
Auto-Priority Detection: I trained a machine learning model that reads the complaint description. If it detects keywords like "Smoke" or "System Failure," it automatically marks the ticket as High Priority, even if the user marked it as low.

Smart Categorization: The AI also predicts if the issue is Hardware, Software, or Network related.

2. Security
Company Code: To register, you need a secret access code (INFO-2026). This prevents strangers from creating accounts.

Email Restriction: The system only allows sign-ups from the company domain (@infomatic.com).

3. Admin Dashboard
Analytics: I added charts to visualize how many tickets are Pending vs. Resolved.

Search Bar: Admins can quickly search for specific tickets by name or subject.

Evidence: Users can upload screenshots of their errors so the admin sees the problem clearly.

4. Communication
Live Chat: There is a comment section inside every ticket where the Admin and User can talk to resolve the issue.

🛠 Tech Stack
Languages: Python, HTML, CSS, JavaScript.

Frameworks: Flask (Backend), Bootstrap 5 (Frontend).

Database: SQLite.

AI Libraries: Scikit-Learn, Pandas (for the prediction model).

📂 How It Works
User Logs In: Enters their corporate email and the secret company code.

Files Complaint: Writes a description (e.g., "The server room is overheating") and uploads a photo.

AI Analysis: The Python backend uses the trained model to analyze the text. It spots the danger and saves the ticket as High Priority.

Admin Resolves: The manager sees the red alert on their dashboard, chats with the user, and marks the ticket as "Resolved."

✅ Project Status
Completed. All features including the AI prediction, file uploads, and security checks are tested and working.