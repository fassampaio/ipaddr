
from ipaddr.ext.database import db
from flask_login import UserMixin
from sqlalchemy.sql import func


class Users(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), unique=True)
    password = db.Column(db.String(200))
    name = db.Column(db.String(100))
    created = db.Column(db.DateTime(timezone=True), default=func.now())
    ip_id = db.relationship('Ipaddresses', backref='users')
    client_id = db.relationship('Clients', backref='clients')
    activity_id = db.relationship('Activity', backref='activity')


class Ipaddresses(db.Model):
    __tablename__ = 'ipaddresses'
    ip_id = db.Column(db.Integer, primary_key=True)
    ipaddress = db.Column(db.String(20))
    location = db.Column(db.String(50))
    created = db.Column(db.DateTime(timezone=True))
    remove = db.Column(db.DateTime(timezone=True))
    owner_ip = db.Column(db.String(50))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))


class Clients(db.Model):
    __tablename__ = 'clients'
    client_id = db.Column(db.Integer, primary_key=True)
    ipaddress = db.Column(db.String(20), unique=True)
    description = db.Column(db.String(100))
    created = db.Column(db.DateTime(timezone=True), default=func.now())
    owner_ip = db.Column(db.String(50))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))


class Activity(db.Model):
    __tablename__ = 'activity'
    activity_id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(20))
    action = db.Column(db.String(20))
    obj = db.Column(db.String(20))
    date = db.Column(db.DateTime(timezone=True), default=func.now())
    owner_ip = db.Column(db.String(50))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
