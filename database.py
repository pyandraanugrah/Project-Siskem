import sqlite3

# koneksi database
conn = sqlite3.connect('database.db')

# cursor
cursor = conn.cursor()

# buat tabel users
cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL
)
''')

print("Database dan tabel berhasil dibuat!")

# simpan perubahan
conn.commit()

# tutup koneksi
conn.close()