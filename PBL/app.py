from flask import Flask, render_template, request, redirect, url_for, session, flash
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash
import os
from cryptography.fernet import Fernet
import base64

app = Flask(__name__)
app.secret_key = '<use your secret key>'

db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': '',  
    'database': '<your database>'
}

key_path = os.path.join(os.path.dirname(__file__), "key.key")

if not os.path.exists(key_path):
    raise FileNotFoundError(f"Encryption key file not found: {key_path}")

with open(key_path, "rb") as key_file:
    encryption_key = key_file.read()

cipher = Fernet(encryption_key)

def get_db_connection():
    try:
        conn = mysql.connector.connect(**db_config)
        return conn
    except mysql.connector.Error as err:
        print(f"Database Error: {err}")
        return None

def encrypt_text(plain_text):
    base64_encoded = base64.b64encode(plain_text.encode()).decode()
    encrypted_text = cipher.encrypt(base64_encoded.encode()).decode()
    return encrypted_text

def decrypt_text(encrypted_text):
    decrypted_base64 = cipher.decrypt(encrypted_text.encode()).decode()
    plain_text = base64.b64decode(decrypted_base64).decode()
    return plain_text

@app.before_request
def require_login():
    if request.endpoint not in ('login', 'register', 'static') and 'user_id' not in session:
        return redirect(url_for('login'))

# Registrasi
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash("Passwords do not match!", "danger")
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT id FROM users WHERE email = %s or username = %s", (email, username))
        if cursor.fetchone():
            cursor.close()
            flash("Email already registered!", "danger")
            return redirect(url_for('register'))

        cursor.execute("INSERT INTO users (email, password,username) VALUES (%s, %s, %s)", (email, hashed_password, username))
        conn.commit()
        cursor.close()
        conn.close()

        flash("Registration successful!", "success")
        return redirect(url_for('login'))

    return render_template('register.html')

# Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email_or_username = request.form['email_or_username']
        password = request.form['password']

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, password FROM users WHERE email = %s or username = %s", (email_or_username, email_or_username))
        user = cursor.fetchone()

        if user and check_password_hash(user[1], password):
            session['user_id'] = user[0]
            cursor.execute("INSERT INTO login_logs (user_id) VALUES (%s)", (user[0],))
            conn.commit()
            
            cursor.close()
            conn.close()
            
            flash("Login successful!", "success")
            return redirect(url_for('index'))
        else:
            cursor.close()
            conn.close()
            flash("Invalid email/username or password!", "danger")
            return redirect(url_for('login'))

    return render_template('login.html')

# Route untuk mengubah password
@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if 'user_id' not in session:
        flash('You need to login first!', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_new_password = request.form.get('confirm_new_password')

        # Validasi input
        if not new_password or not confirm_new_password:
            flash("All fields are required!", "danger")
            return redirect(url_for('reset_password'))

        if new_password != confirm_new_password:
            flash("New passwords do not match!", "danger")
            return redirect(url_for('reset_password'))

        # Hash password baru
        hashed_password = generate_password_hash(new_password)

        # Update password di database
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET password = %s WHERE id = %s", (hashed_password, session['user_id']))
        conn.commit()
        cursor.close()
        conn.close()

        flash("Password updated successfully!", "success")
        return redirect(url_for('login'))

    return render_template('reset_password.html')

# Halaman Utama (HOME)
@app.route('/')
def index():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT id, title, content, last_update FROM notes WHERE user_id = %s", (session['user_id'],))
    notes = cursor.fetchall()

    for note in notes:
        note['title'] = decrypt_text(note['title'])
        note['content'] = decrypt_text(note['content'])

    cursor.close()
    conn.close()
    return render_template('index.html', notes=notes)

# Nambahin catatan
@app.route('/add', methods=['GET', 'POST'])
def add_note():
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']

        encrypted_title = encrypt_text(title)
        encrypted_content = encrypt_text(content)

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO notes (title, content, user_id) VALUES (%s, %s, %s)",
            (encrypted_title, encrypted_content, session['user_id']),
        )
        conn.commit()
        cursor.close()
        conn.close()

        flash("Note added successfully!", "success")
        return redirect(url_for('index'))
    return render_template("add_note.html")


# Mengedit Note
@app.route('/edit_note/<int:note_id>', methods=['GET', 'POST'])
def edit_note(note_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT id, title, content FROM notes WHERE id = %s AND user_id = %s", (note_id, session['user_id']))
    note = cursor.fetchone()

    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']

        encrypted_title = encrypt_text(title)
        encrypted_content = encrypt_text(content)

        cursor.execute("UPDATE notes SET title = %s, content = %s WHERE id = %s", (encrypted_title, encrypted_content, note_id))
        conn.commit()
        cursor.close()
        conn.close()

        flash("Note updated successfully!", "success")
        return redirect(url_for('index'))

    cursor.close()
    conn.close()

    if note:
        note['title'] = decrypt_text(note['title'])
        note['content'] = decrypt_text(note['content']) 
        return render_template('edit_note.html', note=note)
    return "Note not found or you don't have access.", 404

#Menghapus note
@app.route('/delete_note/<int:note_id>', methods=['POST'])
def delete_note(note_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("DELETE FROM notes WHERE id = %s AND user_id = %s", (note_id, session['user_id']))
    conn.commit()
    cursor.close()
    conn.close()
    
    return '', 200

if __name__ == '__main__':
    app.run(debug=True)
