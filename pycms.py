#!/usr/bin/env python
# -*- coding utf-8 -*-

import time
import hmac
from flask import Flask, request, redirect, jsonify
from flask_wtf.csrf import CSRFProtect
from flask_sqlalchemy import SQLAlchemy

# app init
app = Flask(__name__)
csrf = CSRFProtect(app)
db = SQLAlchemy(app)


# config items
SECRET = 'MySuperSecret'
SALT = 'MySuperSalt'
ADMIN_URL = 'admin'


# models
class User(db.Model):
    """ User Table Model Class """
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    pwd = db.Column(db.String, nullable=False)
    created = db.Column(db.Float, default=time.time())

    """ User Table Relationships """
    userRole = db.relationships(
        'Roles', lazy='select', backref=db.backref('user', lazy='joined')
    )

    def __init__(self, password):
        """ Save the password hash instead of the password """
        pwd = self.setPwd(password)

    @staticmethod
    def setPwd(pwd):
        """
        return: the hash of the password.
        params: password to be hashed.
        """
        hashPwd = hmac.new(SALT, pwd)
        return hashPwd

    def checkPwd(self, pwd):
        """
        return: boolean value.
        params: get a string as password and compare it to
        database hash.
        """
        hashPwd = hmac.new(SALT, pwd)
        if self.pwd == hashPwd:
            return True

    def getUser(self):
        """
        return: user data.
        """
        data['user'] = {
            'id': self.id,
            'name': self.name,
        }
        return data


class Roles(db.Model):
    """ Roles Table Model Class """
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)

    """ Roles Tables Relationships """
    userId = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)


def headerCheck(**kwargs):
    for k, v in kwargs:
        timestamp = k['timestamp']
        userId = k['userId']

        if k['signature']:
            pubKey = k['pubKey']
            hashSignature = k['signature']
            return [userId, pubKey, hashSignature, timestamp]
        else:
            return [userId, timestamp]


@app.route('/alive')
def alive():
    header = request.header
    data = headerCheck(header)
    return jsonify({'msg': 'server alive', 'data': data})


@app.route('/userData')
def userData(**kwargs):
    for k, v in kwargs:
        user = User.query.filter_by(id=k['userId']).first_or_404()
        return jsonify({'data': user})


@app.route('/%' % ADMIN_URL)
def adminRoles(**kwargs):
    for k, v in kwargs:
        userRoles = Roles.query.filter_by(userId=k['userId']).first()
        return jsonify({'data': userRoles})


if __name__ == '__main__':
    app.run()
