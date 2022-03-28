from flask import redirect, render_template, request, session
from flask_app import app
from flask_app.models.user import User
from flask_bcrypt import Bcrypt
bcrypt = Bcrypt(app) 

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect('/dashboard')
    return render_template('index.html')

@app.route('/create/user', methods = ['POST'])
def register_user():
    if not User.validate(request.form):
        return redirect('/')
    pw_hash = bcrypt.generate_password_hash(request.form['password'])
    data = {
        "first_name" : request.form['first_name'],
        "last_name" : request.form['last_name'],
        "email" : request.form['email'],
        "password" : pw_hash
    }
    user_id = User.create(data)
    session['user_id'] = user_id
    print(session['user_id'])
    return redirect ('/dashboard')

@app.route ('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect('/')
    id = session['user_id']
    data = {
        'id' : id
    }
    user = User.get_one_by_id(data)
    return render_template('success.html', user =  user)

@app.route('/login', methods=['POST'])
def login():
    print(request.form)
    if not User.login_validate(request.form):
        return redirect('/')
    user = User.get_one(request.form)
    session['user_id'] = user.id
    return redirect('/dashboard')

@app.route('/logout')
def logout():
    del session['user_id']
    return redirect('/')