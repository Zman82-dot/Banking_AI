from flask import Flask, render_template, request, redirect, url_for, session, flash,jsonify
import sqlite3
import bcrypt
import os
import openai
from datetime import datetime

app = Flask(__name__)
app.secret_key = '1f890437d52010780b49babaf6bd1a27f4d54d1700fb8659'
openai.api_key = os.getenv('OPENAI_API_KEY', 'sk-nXQH2VQvAGwc8j3Qcp7SxmLq0T3q5fztya6vrzciI0T3BlbkFJjy_S1CWpcv2WTs5XQviUywN6NycjUDT9SZF3Q1JOsA')
def get_db_connection():
    conn = sqlite3.connect('accounts.db')
    conn.row_factory = sqlite3.Row
    return conn
def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users(
      username TEXT PRIMARY KEY,
      hashed_password TEXT,
      checking REAL,
      savings REAL
    )
    ''')
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS transactions(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT,
      transaction_type TEXT,
      amount REAL,
      new_balance REAL,
      timestamp TEXT,  -- Add a timestamp column
      FOREIGN KEY(username) REFERENCES users(username)
    )
    ''')
    conn.commit()
    conn.close()


@app.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('account'))
    return render_template('index.html')
