# ExamPrep – Online Exam Preparation Portal

ExamPrep is a web-based exam preparation platform developed as part of a **Full Stack Development (FSD) academic project**.  
The application allows students to attempt MCQ-based quizzes across multiple subjects, while administrators manage the complete quiz system.

---

## Project Objective

The objective of this project is to design and develop a full-stack web application that:
- Enables students to practice quizzes online
- Allows an administrator to manage subjects, chapters, quizzes, and questions
- Demonstrates the use of Flask, SQLite, and Bootstrap in a real-world scenario

---

## Features

### User Features
- User registration and login
- View subjects and available quizzes
- Attempt timed MCQ-based quizzes
- View quiz results and past attempts
- Performance statistics and charts

### Admin Features
- Predefined admin login (no registration)
- Admin dashboard with system statistics
- Create, edit, and delete:
  - Subjects
  - Chapters
  - Quizzes
  - MCQ questions
- View registered users and quiz performance

---

## Tech Stack

### Frontend
- HTML5
- CSS3
- Bootstrap 5
- JavaScript
- Jinja2 Templating

### Backend
- Python
- Flask Framework

### Database
- SQLite3

### Version Control & Hosting
- Git & GitHub
- Render (Cloud Deployment)

---

## Project Structure

FSD Project/
│
├── app.py # Main Flask application
├── create_db.py # Database initialization
├── schema.sql # Database schema
├── exam_prep.db # SQLite database
├── requirements.txt # Python dependencies
│
├── templates/ # HTML templates (Jinja2)
├── static/ # CSS and JavaScript files
└── venv/ # Virtual environment


---

## Admin Credentials

- **Email:** admin@admin.local  
- **Password:** Admin@123  

(Admin credentials are predefined and not created through registration.)

---

## Live Deployment

The application is deployed on Render:

🔗 **Live URL:**  
https://the-exam-hub.onrender.com

---

## How to Run Locally

1. Clone the repository

git clone https://github.com/lakshmimoorthy238/fsd-exam-portal.git

2. Navigate to the project folder

cd fsd-exam-portal

3. Create and activate virtual environment

python -m venv venv
venv\Scripts\activate

4. Install dependencies
pip install -r requirements.txt

markdown
Copy code

5. Run the application
python app.py

markdown
Copy code

6. Open in browser
http://127.0.0.1:5000

yaml
Copy code

---

## Notes

- SQLite is used for simplicity and academic purposes.
- On free cloud hosting, database data may reset on redeployment.
- This project is intended for educational demonstration only.

---

## Author

Developed by **Lakshmi**  
(Full Stack Development Academic Project)
