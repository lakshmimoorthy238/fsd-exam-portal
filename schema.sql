-- schema.sql
PRAGMA foreign_keys = ON;

-- Users table (role distinguishes admin vs user)
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    full_name TEXT,
    qualification TEXT,
    dob TEXT,
    role TEXT NOT NULL CHECK(role IN ('admin','user')) DEFAULT 'user',
    created_on TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Subjects
CREATE TABLE IF NOT EXISTS subjects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    description TEXT,
    created_on TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Chapters (belongs to a subject)
CREATE TABLE IF NOT EXISTS chapters (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    subject_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    created_on TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY(subject_id) REFERENCES subjects(id) ON DELETE CASCADE
);

-- Quizzes (belongs to a chapter)
CREATE TABLE IF NOT EXISTS quizzes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    chapter_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    start_datetime TEXT,        -- ISO string e.g. 2025-11-16T10:00:00 (UTC)
    duration_minutes INTEGER,   -- duration in minutes (HH*60 + MM)
    is_active INTEGER DEFAULT 1,
    created_on TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY(chapter_id) REFERENCES chapters(id) ON DELETE CASCADE
);

-- Questions (belongs to a quiz). MCQ with one correct option.
CREATE TABLE IF NOT EXISTS questions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    quiz_id INTEGER NOT NULL,
    question_text TEXT NOT NULL,
    option_a TEXT NOT NULL,
    option_b TEXT NOT NULL,
    option_c TEXT NOT NULL,
    option_d TEXT NOT NULL,
    correct_option TEXT NOT NULL CHECK(correct_option IN ('A','B','C','D')),
    created_on TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY(quiz_id) REFERENCES quizzes(id) ON DELETE CASCADE
);

-- Scores / Attempts
CREATE TABLE IF NOT EXISTS scores (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    quiz_id INTEGER NOT NULL,
    score INTEGER NOT NULL,
    total INTEGER NOT NULL,
    taken_on TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(quiz_id) REFERENCES quizzes(id)
);

