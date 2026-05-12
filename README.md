# Secure Login Website with Argon2

A secure authentication website built using Flask, SQLite, and Argon2 password hashing.

## Features

- User Register
- User Login
- Session Authentication
- Change Password
- Delete Account
- Secure Password Hashing with Argon2

## Technologies Used

- Python
- Flask
- SQLite
- Argon2
- HTML/CSS

## Installation

Install dependencies:

```bash
pip install flask
pip install argon2-cffi
```

Run the application:

```bash
python app.py
```

Open browser:

```text
http://127.0.0.1:5000
```

## Project Structure

```text
Project-Siskem/
│
├── app.py
├── database.py
├── templates/
├── static/
```

## Security

This project uses Argon2 password hashing to securely store user passwords in the database.
