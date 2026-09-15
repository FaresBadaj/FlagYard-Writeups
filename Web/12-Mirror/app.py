import sqlite3, os
from hashlib import md5
from flask import Flask, request, render_template, redirect, session, flash, url_for


def db_connection():
    con = sqlite3.connect('users.db')
    con.row_factory = sqlite3.Row
    return con


app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or '4cf129f6c1e7d7a7a96d944b78a935ac'
db = db_connection()
db.execute('drop table if exists users')
db.execute('create table users(username text primary key, password text not null)')
db.execute('insert into users values ("flag", "219c6a04e9e326e53e61e356694089c9")') # Believe me, this can't be cracked!
db.commit()


@app.route('/sign_up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'GET':
        return render_template('sign_up.html')

    username, password = request.form.get('username').strip(), request.form.get('password')
    if username and password:
        try:
            db = db_connection()
            db.execute('insert into users values(lower(?), ?)', (username, md5(password.encode()).hexdigest()))
            db.commit()
            flash(f'User {username} created', 'message')
            return redirect(url_for('login'))

        except sqlite3.IntegrityError:
            flash('Username is already registered', 'error')
        except sqlite3.Error:
            flash('An error occurred', 'error')
        return redirect(url_for('sign_up'))

    flash(f'Enter username and password', 'error')
    return redirect(url_for('sign_up'))


@app.route('/')
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')

    db = db_connection()
    username, password = request.form.get('username').strip(), request.form.get('password')
    if username and password:
        logged_in = db.execute('select username from users where username=lower(?) and password=?',
                               (username, md5(password.encode()).hexdigest())).fetchone()
        if logged_in:
            session['user'] = logged_in['username'].capitalize()
            return redirect(url_for('account'))

        flash('Invalid credentials', 'error')
        return redirect(url_for('login'))

    flash('Enter username and password to login', 'error')
    return redirect(url_for('login'))


@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))


@app.route('/account')
def account():
    user = session.get('user')
    if user:
        if user == 'Flag':
            return render_template('account.html', user=user, secret=open('flag.txt').read())
        return render_template('account.html', user=user)
    return redirect('/login')


