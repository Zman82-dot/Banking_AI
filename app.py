from flask import Flask, render_template, request, redirect, url_for, session, flash,jsonify
import sqlite3
import bcrypt
import os
import openai
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'secret-key'
openai.api_key = os.getenv('OPENAI_API_KEY', 'apikey')
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

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT hashed_password FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        if result and bcrypt.checkpw(password.encode('utf-8'), result['hashed_password']):
            session['username'] = username
            flash('Login successful')
            return redirect(url_for('account'))
        else:
            flash('Login failed. Incorrect username or password')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        if password != confirm_password:
            flash('Passwords do not match. Please try again.')
            return redirect(url_for('register'))
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            flash('Username already exists. Please login.')
            conn.close()
            return redirect(url_for('login'))
        else:
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            cursor.execute('''
            INSERT INTO users(username, hashed_password, checking, savings)
            VALUES(?, ?, ?, ?)''', (username, hashed_password, 0, 0))
            conn.commit()
            conn.close()
            flash('Registration successful')
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/account', methods=['POST', 'GET'])
def account():
    if 'username' not in session:
        flash('Please login to access account.')
        return redirect(url_for('login'))
    conn = get_db_connection()
    cursor = conn.cursor()
    username = session['username']
    cursor.execute("SELECT checking, savings FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()
    return render_template('account.html', checking=row['checking'], savings=row['savings'])
@app.route('/account', methods=['POST', 'GET'])
def total_balance(checking_balance,savings_balance):
    checking_balance += savings_balance == total_balance
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO transactions total_balance")
    conn.close()
    return total_balance(), render_template('account.html')
@app.route('/transaction', methods=['POST', 'GET'])
def transaction():
    if 'username' not in session:
        flash('Please login to perform transactions')
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor()
    action = request.form['action']
    amount = float(request.form['amount'])
    username = session['username']
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')  # Get current time

    cursor.execute("SELECT checking, savings FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    checking_balance = row['checking']
    savings_balance = row['savings']

    if action == "deposit_checking":
        checking_balance += amount
        cursor.execute("UPDATE users SET checking = ? WHERE username = ?", (checking_balance, username))
        cursor.execute("INSERT INTO transactions(username, transaction_type, amount, new_balance, timestamp) VALUES(?, ?, ?, ?, ?)",
                       (username, action, amount, checking_balance, timestamp))

    elif action == "deposit_savings":
        savings_balance += amount
        cursor.execute("UPDATE users SET savings = ? WHERE username = ?", (savings_balance, username))
        cursor.execute("INSERT INTO transactions(username, transaction_type, amount, new_balance, timestamp) VALUES(?, ?, ?, ?, ?)",
                       (username, action, amount, savings_balance, timestamp))

    elif action == "withdraw_checking":
        if amount > checking_balance:
            flash('Insufficient funds, try a lower amount')
            return redirect(url_for('account'))
        checking_balance -= amount
        cursor.execute("UPDATE users SET checking = ? WHERE username = ?", (checking_balance, username))
        cursor.execute("INSERT INTO transactions(username, transaction_type, amount, new_balance, timestamp) VALUES(?, ?, ?, ?, ?)",
                       (username, action, -amount, checking_balance, timestamp))

    elif action == "withdraw_savings":
        if amount > savings_balance:
            flash('Insufficient funds, try a lower amount.')
            return redirect(url_for('account'))
        savings_balance -= amount
        cursor.execute("UPDATE users SET savings = ? WHERE username = ?", (savings_balance, username))
        cursor.execute("INSERT INTO transactions(username, transaction_type, amount, new_balance, timestamp) VALUES(?, ?, ?, ?, ?)",
                       (username, action, -amount, savings_balance, timestamp))

    elif action == "transfer_checking_to_savings":
        if amount > checking_balance:
            flash('Insufficient funds')
            return redirect(url_for('account'))
        checking_balance -= amount
        savings_balance += amount
        cursor.execute("UPDATE users SET checking = ?, savings = ? WHERE username = ?", (checking_balance, savings_balance, username))
        cursor.execute("INSERT INTO transactions(username, transaction_type, amount, new_balance, timestamp) VALUES(?, ?, ?, ?, ?)",
                       (username, action, -amount, checking_balance, timestamp))
        cursor.execute("INSERT INTO transactions(username, transaction_type, amount, new_balance, timestamp) VALUES(?, ?, ?, ?, ?)",
                       (username, action, amount, savings_balance, timestamp))

    elif action == "transfer_savings_to_checking":
        if amount > savings_balance:
            flash('Insufficient funds')
            return redirect(url_for('account'))
        savings_balance -= amount
        checking_balance += amount
        cursor.execute("UPDATE users SET checking = ?, savings = ? WHERE username = ?", (checking_balance, savings_balance, username))
        cursor.execute("INSERT INTO transactions(username, transaction_type, amount, new_balance, timestamp) VALUES(?, ?, ?, ?, ?)",
                       (username, action, amount, checking_balance, timestamp))
        cursor.execute("INSERT INTO transactions(username, transaction_type, amount, new_balance, timestamp) VALUES(?, ?, ?, ?, ?)",
                       (username, action, -amount, savings_balance, timestamp))

    conn.commit()
    conn.close()
    flash('Transaction successful')
    return redirect(url_for('account'))

@app.route('/history', methods=['GET'])
def transaction_history():
    if 'username' not in session:
        flash('Please login to view transaction history.')
        return redirect(url_for('login'))

    username = session['username']
    conn = get_db_connection()
    cursor = conn.cursor()

    # Fetch the user's transaction history
    cursor.execute("SELECT transaction_type, amount, new_balance, timestamp FROM transactions WHERE username = ? ORDER BY timestamp DESC", (username,))
    transactions = cursor.fetchall()
    conn.close()

    # Render the transaction history template and pass transactions data
    return render_template('history.html', transactions=transactions)


@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('You have been logged out.')
    return redirect(url_for('index'))

def get_completion_from_messages(messages, model="gpt-3.5-turbo", temperature=0):
    response = openai.ChatCompletion.create(
        model=model,
        messages=messages,
        temperature=temperature,
    )
    return response.choices[0].message["content"]

# Existing banking application routes


# New chatbot route for customer service
# New chatbot route for customer service
@app.route('/chatbot', methods=['GET', 'POST'])
def chatbot():
    if request.method == 'POST':
        prompt = request.form.get('prompt')  # Get user input from form
        if not prompt:
            return jsonify({'response': 'Please enter a valid question.'})

        # Access the user's account information and/or transaction history from the database
        user_info = {}
        transactions = []

        # Only check account info and transaction history if the user is logged in
        if 'username' in session:
            username = session['username']
            conn = get_db_connection()
            cursor = conn.cursor()

            # Check if user asks about balance, account, or transaction history
            if 'balance' in prompt.lower() or 'account' in prompt.lower():
                cursor.execute("SELECT checking, savings FROM users WHERE username = ?", (username,))
                user_info = cursor.fetchone()
                if user_info:
                    checking_balance = user_info['checking']
                    savings_balance = user_info['savings']
                    user_info = {
                        'checking_balance': checking_balance,
                        'savings_balance': savings_balance
                    }

            if 'transaction history' in prompt.lower() or 'transactions' in prompt.lower():
                # Fetch the user's transaction history
                cursor.execute("SELECT transaction_type, amount, new_balance, timestamp FROM transactions WHERE username = ? ORDER BY timestamp DESC", (username,))
                transactions = cursor.fetchall()

            conn.close()

        else:
            return jsonify({'response': 'Please log in to access your account information.'})

        # Prepare the system's context
        context = [
            {'role': 'system', 'content': 'You are a helpful customer service assistant for a banking application.'},
            {'role': 'user', 'content': prompt}
        ]

        # If user account info is available, add it to the system context
        if user_info:
            context.append({
                'role': 'system',
                'content': f"User's checking balance is {user_info['checking_balance']} and savings balance is {user_info['savings_balance']}."
            })

        # If transaction history is available, format it into a user-friendly response
        if transactions:
            transaction_list = "\n".join([f"{t['timestamp']}: {t['transaction_type']} of ${t['amount']} (new balance: ${t['new_balance']})" for t in transactions])
            context.append({
                'role': 'system',
                'content': f"User's recent transactions are:\n{transaction_list}"
            })

        # Get the AI response from OpenAI
        response = get_completion_from_messages(context)

        return jsonify({'response': response})  # Return response as JSON for AJAX

    return render_template('chatbot.html')  # Render chatbot HTML template for user interaction

if __name__ == '__main__':
    init_db()
    app.run(debug=True)