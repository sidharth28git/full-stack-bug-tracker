# full-stack-bug-tracker
Full Stack Bug Tracker

A web-based Bug Management System built using Python, Flask, SQLite, HTML, and CSS.
This application simulates a real-world Software Development Life Cycle (SDLC) workflow, enabling teams to report, assign, track, and resolve software issues efficiently.

Features

Role-based authentication (Reporter, Developer, Admin)

CRUD operations for bug management

Status workflow: Open → In Progress → Resolved → Closed

Severity tracking (Low, Medium, High, Critical)

Dashboard with bug metrics and assignments

Secure password hashing and session management

Tech Stack

Backend: Python, Flask

Database: SQLite

Frontend: HTML, CSS

Version Control: Git, GitHub

Setup Instructions

Clone the repository:

git clone <your-repo-link>
cd Full-Stack-Bug-Tracker


Create and activate virtual environment:

Windows

python -m venv venv
venv\Scripts\activate


Mac/Linux

python3 -m venv venv
source venv/bin/activate


Install dependencies:

pip install -r requirements.txt


Initialize database:

python init_db.py


Run the application:

python app.py


Open http://127.0.0.1:5000 in your browser.

Purpose

This project demonstrates full-stack development, database integration, authentication, workflow management, debugging, and SDLC understanding, simulating how real software teams manage issues.
