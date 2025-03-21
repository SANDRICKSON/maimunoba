from extensions import db, login_manager
from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime
from sqlalchemy.orm import relationship


class BaseModel:
    def create(self):
        db.session.add(self)
        db.session.commit()

    def delete(self):
        db.session.delete(self)
        db.session.commit()

    @staticmethod
    def save():
        db.session.commit()


class User(db.Model, BaseModel, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, nullable=False, unique=True)  
    email = db.Column(db.String, nullable=False, unique=True)  
    _password_hash = db.Column("password", db.String, nullable=False)  # შეცვლილი ველის სახელი

    country = db.Column(db.String)
    gender = db.Column(db.String)
    birthday = db.Column(db.Date)
    is_verified = db.Column(db.Boolean, default=False)
    avatar = db.Column(db.String(255), nullable=True, default='default.png')
    is_admin = db.Column(db.Boolean, default=False)  

    @property
    def password(self):
        raise AttributeError("Password is not accessible!")  # პაროლის დაბრუნება დაუშვებელია

    @password.setter
    def password(self, value):
        if not value:
            raise ValueError("Password cannot be empty.")
        self._password_hash = generate_password_hash(value)
    
    def check_password(self, password):
        return check_password_hash(self._password_hash, password)



class ContactMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    user_email = db.Column(db.String(120), nullable=False)  
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False) 

    def __repr__(self):
        return f"<ContactMessage {self.username}: {self.message[:20]}>"


class Reply(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message_id = db.Column(db.Integer, db.ForeignKey('contact_message.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    reply_text = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    message = db.relationship("ContactMessage", backref="replies")
    user = db.relationship("User", backref="user_replies")
