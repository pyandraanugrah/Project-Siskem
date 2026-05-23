from flask import Flask, render_template, request, session, redirect, flash
from datetime import timedelta 
from argon2 import PasswordHasher
import time 
import sqlite3

app = Flask(__name__)

# =========================  
# SESSION TIMEOUT
# =========================
app.permanent_session_lifetime = timedelta(minutes=5)    

# Secret key untuk session
app.secret_key = 'secret123'

# =========================
# AUTO SESSION CHECK
# ========================= 
@app.before_request
def session_timeout():

    session.permanent = True

    # reset timer setiap ada aktivitas
    session.modified = True

# Argon2 Password Hasher
ph = PasswordHasher()

# ========================= 
# LOGIN ATTEMPT LIMITER
# =========================
login_attempts = {} 

# =========================
# HALAMAN REGISTER
# =========================
@app.route('/')
def home():
    return render_template('register.html')

# =========================
# PROSES REGISTER
# =========================
@app.route('/register', methods=['POST'])
def register():

    username = request.form['username']

    password = request.form['password']

    security_question = request.form['security_question']

    security_answer = request.form['security_answer']

    # =========================
    # PASSWORD VALIDATION
    # =========================

    # minimal 8 karakter
    if len(password) < 8:

        flash("Password minimal 8 karakter!", "error")

        return redirect('/')

    # harus ada huruf besar
    if not any(char.isupper() for char in password):

        flash("Password harus mengandung huruf besar!", "error")

        return redirect('/')

    # harus ada angka
    if not any(char.isdigit() for char in password):

        flash("Password harus mengandung angka!", "error")

        return redirect('/')

    # harus ada simbol
    symbols = "!@#$%^&*()_+-="

    if not any(char in symbols for char in password):

        flash("Password harus mengandung simbol!", "error")

        return redirect('/')

    # =========================
    # HASH PASSWORD & ANSWER
    # =========================

    hashed_password = ph.hash(password)

    hashed_answer = ph.hash(security_answer)

    # =========================
    # DATABASE
    # =========================

    conn = sqlite3.connect('database.db')

    cursor = conn.cursor()

    try:

        cursor.execute(
            """
            INSERT INTO users (
                username,
                password,
                security_question,
                security_answer
            )
            VALUES (?, ?, ?, ?)
            """,
            (
                username,
                hashed_password,
                security_question,
                hashed_answer
            )
        )

        conn.commit()

        conn.close()

        flash("Register berhasil! Silakan login.", "success")

        return redirect('/login')

    except:

        conn.close()

        flash("Username sudah digunakan!", "error")

        return redirect('/')

# =========================
# HALAMAN LOGIN
# =========================
@app.route('/login')
def login_page():
    return render_template('login.html')

# =========================
# PROSES LOGIN
# =========================
@app.route('/login', methods=['POST'])
def login():

    username = request.form['username']
    password = request.form['password']

        # =========================
    # CEK APAKAH USER DI-LOCK
    # =========================

    if username in login_attempts:

        user_data = login_attempts[username]

        # cek apakah masih dalam masa lock
        if time.time() < user_data["lock_until"]:

            remaining = int(
                user_data["lock_until"] - time.time()
            )

            flash(
                f"Terlalu banyak percobaan login! Coba lagi dalam {remaining} detik.",
                "error"
            )

            return redirect('/login') 

    # Koneksi database
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # Cari user berdasarkan username
    cursor.execute(
        "SELECT password FROM users WHERE username = ?",
        (username,)
    )

    result = cursor.fetchone()

    conn.close()

    # Jika user tidak ditemukan
    if result is None:
        flash("User tidak ditemukan!", "error")
        return redirect('/login')

    stored_hash = result[0]

    # Verifikasi password menggunakan Argon2
    try:
        ph.verify(stored_hash, password)

        # reset login attempts
        if username in login_attempts:

            login_attempts[username]["attempts"] = 0

        session.permanent = True

        # Simpan session login
        session['username'] = username

        return redirect('/dashboard')
    
    except:

        # =========================
        # LOGIN GAGAL
        # =========================

        if username not in login_attempts:

            login_attempts[username] = {
                "attempts": 0,
                "lock_until": 0
            } 

        login_attempts[username]["attempts"] += 1

        attempts = login_attempts[username]["attempts"]

        # jika gagal 5x
        if attempts >= 5:

            # lock 1 menit
            login_attempts[username]["lock_until"] = time.time() + 60

            flash(
                "Terlalu banyak percobaan login! Akun dikunci 1 menit.",
                "error"
            )

            return redirect('/login')

        flash(
            f"Password salah! Percobaan ke-{attempts}/5",
            "error"
        )

        return redirect('/login')
    
        
# DASHBOARD
# =========================
@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        flash("Session expired. Silakan login kembali.", "error")
        return redirect('/login')

    return render_template(
        'dashboard.html',
        username=session['username']
    )

@app.route('/delete_account')
def delete_account():

    # cek login
    if 'username' not in session:
        flash("Session expired. Silakan login kembali.", "error")
        return redirect('/login')

    username = session['username']

    # koneksi database
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # hapus user
    cursor.execute(
        "DELETE FROM users WHERE username = ?",
        (username,)
    )

    conn.commit()
    conn.close()

    # logout session
    session.pop('username', None)

    flash(
        "Akun berhasil dihapus!",
        "success"
)

    return redirect('/login')

# halaman change password
@app.route('/change_password')
def change_password_page():

    # cek login
    if 'username' not in session:
        flash("Session expired. Silakan login kembali.", "error")
        return redirect('/login')

    return render_template('change_password.html')

# proses change password
# proses change password
@app.route('/change_password', methods=['POST'])
def change_password():

    # cek login
    if 'username' not in session:

        flash(
            "Session expired. Silakan login kembali.",
            "error"
        )

        return redirect('/login')

    username = session['username']

    old_password = request.form['old_password']

    new_password = request.form['new_password']

    # koneksi database
    conn = sqlite3.connect('database.db')

    cursor = conn.cursor()

    # ambil hash password lama
    cursor.execute(
        "SELECT password FROM users WHERE username = ?",
        (username,)
    )

    result = cursor.fetchone()

    if result is None:

        conn.close()

        flash(
            "User tidak ditemukan!",
            "error"
        )

        return redirect('/dashboard')

    stored_hash = result[0]

    try:

        # verify password lama
        ph.verify(stored_hash, old_password)

        # hash password baru
        new_hash = ph.hash(new_password)

        # update password
        cursor.execute(
            """
            UPDATE users
            SET password = ?
            WHERE username = ?
            """,
            (new_hash, username)
        )

        conn.commit()

        conn.close() 

        flash(
            "Password berhasil diubah!",
            "success"
        )

        return redirect('/dashboard')

    except:

        conn.close()

        flash(
            "Password lama salah!",
            "error"
        )

        return redirect('/change_password')
    # =========================
# HALAMAN FORGOT PASSWORD
# =========================
@app.route('/forgot_password')
def forgot_password_page():

    return render_template('forgot_password.html')


# =========================
# PROSES FORGOT PASSWORD
# =========================
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():

    # =========================
    # JIKA GET
    # =========================
    if request.method == 'GET':

        return render_template(
            'forgot_password.html'
        )

    # =========================
    # AMBIL USERNAME
    # =========================
    username = request.form['username']

    # koneksi database
    conn = sqlite3.connect('database.db')

    cursor = conn.cursor()

    # ambil data user
    cursor.execute(
        """
        SELECT security_question, security_answer
        FROM users
        WHERE username = ?
        """,
        (username,)
    )

    result = cursor.fetchone()

    # jika user tidak ditemukan
    if result is None:

        conn.close()

        flash("Username tidak ditemukan!", "error")

        return redirect('/forgot_password')

    security_question = result[0]

    stored_answer = result[1]

    # =========================
    # TAHAP 1
    # USER BARU INPUT USERNAME
    # =========================
    if 'security_answer' not in request.form:

        conn.close()

        return render_template(
            'forgot_password.html',
            username=username,
            security_question=security_question
        )

    # =========================
    # TAHAP 2
    # VERIFY ANSWER
    # =========================

    security_answer = request.form['security_answer']

    new_password = request.form['new_password']

    confirm_password = request.form['confirm_password']

    # cek konfirmasi password
    if new_password != confirm_password:

        conn.close()

        flash("Konfirmasi password tidak cocok!", "error")

        return redirect('/forgot_password')

    try:

        # verify security answer
        ph.verify(
            stored_answer,
            security_answer
        )

        # hash password baru
        new_hash = ph.hash(new_password)

        # update password
        cursor.execute(
            """
            UPDATE users
            SET password = ?
            WHERE username = ?
            """,
            (new_hash, username)
        )

        conn.commit()

        conn.close()

        flash(
            "Password berhasil direset!",
            "success"
        )

        return redirect('/login')

    except:

        conn.close()

        flash(
            "Jawaban security question salah!",
            "error"
        )

        return redirect('/forgot_password')

# =========================
# LOGOUT
# =========================
@app.route('/logout')
def logout():

    # Hapus session
    session.pop('username', None)

    return redirect('/login')

# =========================
# JALANKAN FLASK
# =========================
if __name__ == '__main__':
    app.run(debug=True)