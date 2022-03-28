import bcrypt
from flask import flash
from flask_bcrypt import Bcrypt
from flask_app import app
from flask_app.config.mysqlconnection import connectToMySQL
import re
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
bcrypt = Bcrypt(app)

class User:
    def __init__(self,data):
        self.id = data['id']
        self.first_name = data['first_name']
        self.last_name = data['last_name']
        self.email = data['email']
        self.password = data['password']
        self.created_at = data['created_at']
        self.updated_at = data['updated_at']

    @classmethod
    def create(self,data):
        query ='INSERT INTO users (first_name, last_name, email, password, created_at, updated_at) VALUES (%(first_name)s, %(last_name)s, %(email)s, %(password)s, NOW(), NOW());'
        results = connectToMySQL('login_schema').query_db(query,data)
        return results

    @classmethod
    def get_all(cls):
        query = "SELECT * FROM users;"
        results = connectToMySQL('login_schema').query_db(query)
        users = []
        if not results:
            return False
        for row in results:
            users.append( cls(row) )
        return users

    @classmethod
    def get_one(cls, data):
        query = "SELECT * FROM users WHERE email = %(email)s;"
        results = connectToMySQL('login_schema').query_db(query,data)
        if not results:
            return False
        user = cls(results[0])
        return user

    @classmethod
    def get_one_by_id(cls, data):
        query = "SELECT * FROM users WHERE id = %(id)s;"
        results = connectToMySQL('login_schema').query_db(query,data)
        if not results:
            return False
        user = cls(results[0])
        return user

    @staticmethod
    def login_validate(user):
        is_valid = True
        if len(user['email']) < 1:
            flash("Please enter an email.", 'login_email')
            is_valid = False
        if len(user['password']) < 1:
            flash("Please enter a password.", 'login_password')
            is_valid = False
        else:
            data = {
                'email' : user['email']
            }
            potential_user = User.get_one(data)
            if not potential_user:
                is_valid = False
                flash("Login/Password is invalid.", 'invalid_login')
                return is_valid
            if not bcrypt.check_password_hash(potential_user.password, user['password']):
                flash("Login/Password is invalid.", 'invalid_login')
                is_valid = False
        return is_valid

    @staticmethod
    def validate(user):
        is_valid = True
        if len(user['first_name']) < 2:
            flash("First name must be at least 2 characters.", 'first_name')
            is_valid = False
        if len(user['last_name']) < 2:
            flash("Last name must be at least 2 characters.", 'last_name')
            is_valid = False
        if not EMAIL_REGEX.match(user['email']):
            flash("Invalid email address!", 'email')
            is_valid = False
        if len(user['password']) < 8:
            flash("Password must be at least 8 characters.", 'password')
            is_valid = False
        if (user['password']) != (user['confirm_password']):
            flash("Passwords do not match", 'confirm_password')
            is_valid = False
        return is_valid