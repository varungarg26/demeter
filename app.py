import flask
from flask import Flask,render_template, request, jsonify, make_response, url_for,redirect
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager,jwt_required,create_access_token
from flask_mail import Mail, Message
from sqlalchemy import Column, Integer,String, Float, Boolean
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
import sendgrid
from sendgrid.helpers.mail import *
import json
import os
import addon
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
import requests
from functools import wraps
from flask import Flask, session

app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///' + os.path.join(basedir,'users.db')
app.config['SECRET_KEY']='secret-key'





s = URLSafeTimedSerializer('SECRET_KEY')

db=SQLAlchemy(app)
@app.cli.command('dbCreate')
def db_create():
    db.create_all()
    print('Database created')

@app.cli.command('dbDrop')
def db_drop():
    db.drop_all()
    print('Database Dropped')

@app.cli.command('dbSeed')
def db_seed():
    hashed_password=generate_password_hash('password', method='sha256')
    testUser=User(firstName='User',
                    lastName='Test',
                             email='test@gmail.com',
                             phoneNumber='4166666666',
                             password=hashed_password,
                             public_id=str(uuid.uuid4()),
                             groceryList=""
                             )
    db.session.add(testUser)
    db.session.commit()
    print('Seeded')

class User(db.Model):
    id=Column(Integer, primary_key=True)
    public_id=Column(String(50), unique=True)
    firstName=Column(String(50))
    lastName=Column(String(50))
    email=Column(String(50), unique=True)
    phoneNumber=Column(Integer)
    password=Column(String(50))
    groceryList=Column(String(50))

class GroceryList(db.Model):
    id=Column(Integer,primary_key=True)
    list_id=Column(String(50),unique=True)
    GroceryName=Column(String(50))
    dateCreated=Column(String())
    picked=Column(Boolean)
    userPickerUp=Column(String)

    
class Item(db.Model):
    id=Column(Integer,primary_key=True)
    list_id=Column(String(50))
    item_id=Column(String(50),unique=True)
    Username=Column(String())
    ItemName=Column(String())
    Quantity= Column(String())
    Comments=Column(String())
   
    
def token_required(f):
    @wraps(f)
    def decorated(*args,**kwargs):
        token=None
        if 'x-access-tokens' in request.headers:
            token=request.headers['x-access-tokens']
        if not token:
            return jsonify(message='Token is missing'),401
        try:
            data=jwt.decode(token, app.config['SECRET_KEY'])
            current_user=User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify(message='Token is invalid'),401

        return f(current_user, *args, **kwargs)
    return decorated

@app.route('/api/groceryList', methods=['POST'])
@token_required
def portfolioCreate(current_user):
    user_data={}
    user_data['public_id']=current_user.public_id

    gList=request.json
    g=GroceryList.query.filter_by(GroceryName=gList['ListName']).first()
    if g:
        return jsonify(message="List with the same name exists"),401
    else:
        val=str(uuid.uuid4())
        groceryList=GroceryList(
                list_id=val,
                GroceryName=gList['ListName'],
                dateCreated=datetime.datetime.now(),
                picked=False,
                userPickerUp=""
        )
        current_user.groceryList=val
        db.session.add(groceryList)
        db.session.commit()
        return jsonify(message="List Created"),201

@app.route('/api/viewListforUser/<grocery_list>', methods=['GET'])
@token_required
def viewListUser(current_user,grocery_list):
    
    groupList=GroceryList.query.filter_by(list_id=current_user.groceryList).all()
    itemListAll=Item.query.filter_by(Username=current_user.firstName).all()
    output=[]
    allItems=[]
    if groupList:
        if itemListAll:
            for items in itemListAll:
                itemss={}
                itemss['itemName']=items.ItemName
                itemss['quantity']=items.Quantity
                itemss['comment']=items.Comments
                itemss['userName']=items.Username
                allItems.append(itemss)
            return jsonify(items=allItems)
        else:
            return jsonify(message="No items in the list")
    else:
        return jsonify (message="List not found")        

@app.route('/api/viewList/<grocery_list>', methods=['GET'])
@token_required
def viewList(current_user,grocery_list):
    
    groupList=GroceryList.query.filter_by(list_id=current_user.groceryList).all()
    itemListAll=Item.query.filter_by().all()
    output=[]
    allItems=[]
    if groupList:
        if itemListAll:
            for items in itemListAll:
                itemss={}
                itemss['itemName']=items.ItemName
                itemss['quantity']=items.Quantity
                itemss['comment']=items.Comments
                itemss['userName']=items.Username
                allItems.append(itemss)
            return jsonify(items=allItems)
        else:
            return jsonify(message="No items in the list")
    else:
        return jsonify (message="List not found")


@app.route('/api/addtoList/<grocery_list>', methods=['POST'])
@token_required
def addtoList(current_user,grocery_list)S

    new=request.json
    newItem=Item(
                Username=current_user.firstName,
                list_id=grocery_list,
                item_id=str(uuid.uuid4()),
                ItemName=new['ItemName'],
                Quantity=new['Quantity'],
                Comments=new['Comments']
        )
    db.session.add(newItem)
    db.session.commit()
    return jsonify(message="Item Added"),201

@app.route('/api/addUsertoList/<grocery_list>',methods=['POST'])
@token_required
def addUsertoList(current_user,grocery_list):
    current_user.groceryList=grocery_list
    db.session.commit()
    return jsonify(message="User Added to List")

@app.route('/api/picked',methods=['GET'])
@token_required
def volunteer(current_user):
    groupList=GroceryList.query.filter_by(list_id=current_user.groceryList).first()
    groupList.picked=True
    groupList.pickerUser=current_user.firstName
    db.session.commit()
    return jsonify(message="User has Volunteered")



@app.route('/api/getGroceryList',methods=['GET'])
@token_required
def viewListData(current_user):
    groupList=GroceryList.query.filter_by(list_id=current_user.groceryList).first()

    if groupList:
        list_data={}
        list_data['list_id']=groupList.list_id
        list_data['GroceryName']=groupList.GroceryName
        list_data['date']=groupList.dateCreated
        list_data['picked']=groupList.picked
        list_data['pickerUser']=groupList.userPickerUp
        
        return jsonify(message=list_data)
    else:
        return jsonify(message="You don't have a list")

@app.route('/api/getUser',methods=['GET'])
@token_required
def user(current_user):
    user_data={}
    user_data['firstName']=current_user.firstName
    user_data['lastName']=current_user.lastName
    user_data['email']=current_user.email
    user_data['groceryList']=current_user.groceryList
    
    return jsonify(message=user_data)

@app.route('/api/register', methods=['POST'])
def register():
    data=request.json
    emailUser=data['email']

    test=User.query.filter_by(email=emailUser).first()

    if test:
        return jsonify(message='A user with this email already exists.'), 409

    if data['password'] != data['confirmPassword']:
        return jsonify(message='Passwords do not match')
    else:
        hashed_password=generate_password_hash(data['password'], method='sha256')
        new_user=User(
                             public_id=str(uuid.uuid4()),
                             firstName=data['firstName'],
                             lastName=data['lastName'],
                             email=data['email'],
                             phoneNumber=data['phoneNumber'],
                             password=hashed_password
                             )
    
        db.session.add(new_user)
        db.session.commit()
        return jsonify(message='User Created'),201



@app.route('/api/login', methods=['POST'])
def login():
    login=request.json

    user=User.query.filter_by(email=login['email']).first()

    if not user:
        return jsonify(message='A user with this email does not exist.')
    if check_password_hash(user.password,login['password']):
        token=jwt.encode({'public_id': user.public_id,'exp':datetime.datetime.utcnow()+datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
        return jsonify(token=token.decode('UTF-8'))
    else:
        return jsonify(message='Your email or password is incorrect'),401

    
  
if __name__ == '__main__':
    app.debug=True
    app.run()