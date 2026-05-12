from flask import Flask, render_template, request, session, redirect
from argon2 import PasswordHasher
import sqlite3

app = Flask(__name__)

# Secret key untuk session
app.secret_key = 'secret123'

# Argon2 Password Hasher
ph = PasswordHasher()

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

    # Hash password menggunakan Argon2
    hashed_password = ph.hash(password)

    # Koneksi database
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    try:
        # Simpan user ke database
        cursor.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            (username, hashed_password)
        )

        conn.commit()

    except:
        conn.close()
        return "<h2>Username sudah digunakan!</h2>"

    conn.close()

    return """
    <h2>Register Berhasil!</h2>

    <a href="/login">Login Sekarang</a>
    """

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
        return "<h2>User tidak ditemukan!</h2>"

    stored_hash = result[0]

    # Verifikasi password menggunakan Argon2
    try:
        ph.verify(stored_hash, password)

        # Simpan session login
        session['username'] = username

        return redirect('/dashboard')

    except:
        return "<h2>Password salah!</h2>"

# =========================
# DASHBOARD
# =========================
@app.route('/dashboard')
def dashboard():

    # Cek apakah user sudah login
    if 'username' not in session:
        return redirect('/login')

    return render_template(
        'dashboard.html',
        username=session['username']
    )

@app.route('/delete_account')
def delete_account():

    # cek login
    if 'username' not in session:
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

    return "<h2>Akun berhasil dihapus!</h2>"

# halaman change password
@app.route('/change_password')
def change_password_page():

    # cek login
    if 'username' not in session:
        return redirect('/login')

    return render_template('change_password.html')

# proses change password
@app.route('/change_password', methods=['POST'])
def change_password():

    # cek login
    if 'username' not in session:
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
        return "<h2>User tidak ditemukan!</h2>"

    stored_hash = result[0]

    try:
        # verify password lama
        ph.verify(stored_hash, old_password)

        # hash password baru
        new_hash = ph.hash(new_password)

        # update password
        cursor.execute(
            "UPDATE users SET password = ? WHERE username = ?",
            (new_hash, username)
        )

        conn.commit()
        conn.close()

        return """
        <h2>Password berhasil diubah!</h2>

        <a href="/dashboard">Kembali ke Dashboard</a>
        """

    except:
        conn.close()

        return "<h2>Password lama salah!</h2>"

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