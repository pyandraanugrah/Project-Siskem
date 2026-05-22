# Secure Login Website with Argon2

A secure authentication website built using Flask, SQLite, and Argon2 password hashing.

## Features

- User Registration
- User Login
- Session Authentication
- Logout System
- Change Password
- Forgot Password with Security Question
- Delete Account
- Password Strength Meter
- Password Validation
- Show/Hide Password
- Flash Message Notification
- Secure Password Hashing with Argon2
- Security Answer Hashing with Argon2

## Security Features

- Argon2 Password Hashing
- Password Validation
- Password Strength Meter
- Security Question Verification
- Session Authentication
- Hashed Security Answers

 ## Screenshots

### Login Page
![Login]
<img width="1375" height="852" alt="Screenshot 2026-05-22 231542" src="https://github.com/user-attachments/assets/3a33bff1-4c6c-4d3c-917d-d58834c8621e" />


### Register Page
![Register] 
<img width="1376" height="912" alt="image" src="https://github.com/user-attachments/assets/25064d21-4ad2-409f-a815-8f354460f5e1" />



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

Create database:
```bash
python database.py
```

Run the application:

```bash
python app.py
```

Open browser:

```text
http://127.0.0.1:5000
```

## Author

Kelompok 4 Sitem Keamanan 
Dibuat Untuk Projek Sistem Keamanan 

## Future Improvements

- Login Attempt Limiter
- Session Timeout
- CSRF Protection


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
