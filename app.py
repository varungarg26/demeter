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
#import addon
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

SENDGRID_API_KEY = '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'

sg = sendgrid.SendGridAPIClient(api_key=SENDGRID_API_KEY)



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
    picked=Column(Boolean())
    userPickerUp=Column(String(50))

    
class Item(db.Model):
    id=Column(Integer,primary_key=True)
    user_id=Column(String(50))
    list_id=Column(String(50))
    item_id=Column(String(50),unique=True)
    Username=Column(String())
    ItemName=Column(String())
    Quantity= Column(String())
    Comments=Column(String())
   
    
def token_required(f):
    @wraps(f)
    def decorated(*args,**kwargs):
        token = None
        if 'token' not in session:
            return render_template('need-to-login-error.jinja2')
        else:
            if session is None:
                return render_template('need-to-login-error.jinja2')
            if 'cookie' in request.headers:
                token=session['token']
            if 'cookie' not in request.headers:
                return jsonify(message='Token is missing'),401
            try:
                data=jwt.decode(token, app.config['SECRET_KEY'])
                current_user=User.query.filter_by(public_id=data['public_id']).first()
            except:
                return jsonify(message='Token is invalid'),401

            return f(current_user, *args, **kwargs)
    return decorated

@app.route('/api/groceryList')
@token_required
def createList(current_user):
    return render_template('createList.jinja2')

@app.route('/api/groceryList', methods=['POST'])
@token_required
def listCreate(current_user):
    user_data={}
    user_data['public_id']=current_user.public_id

    gList=request.form

    if request.form.get('ListName'):
        g = GroceryList.query.filter_by(GroceryName=gList['ListName']).first()
        if g:
            return jsonify(message="List with the same name exists"),401
        else:
            groceryList=GroceryList(
                    list_id=str(uuid.uuid4()),
                    GroceryName=gList['ListName'],
                    dateCreated=datetime.datetime.now(),
                    picked=False,
                    userPickerUp="none"
            )
            db.session.add(groceryList)
            db.session.commit()

            groceryGroup = GroceryList.query.filter_by(GroceryName=gList['ListName']).first()
            current_user.groceryList = groceryGroup.list_id

            db.session.commit()

            return redirect(url_for('viewListData'))

    elif request.form.get('groceryList'):
        return redirect('/api/addUsertoList/' + gList['groceryList'])

@app.route('/api/addUsertoList/<id>')
@token_required
def addUsertoList(current_user, id):
    groceryGroup = GroceryList.query.filter_by(list_id=id).first()
    current_user.groceryList = groceryGroup.list_id
    db.session.commit()
    return redirect(url_for('viewListData'))


@app.route('/api/viewListforUser/<grocery_list>', methods=['GET'])
@token_required
def viewListUser(current_user, grocery_list):
    groupList = GroceryList.query.filter_by(list_id=current_user.groceryList).all()
    itemListAll = Item.query.filter_by(Username=current_user.firstName).all()
    output = []
    allItems = []
    if groupList:
        if itemListAll:
            for items in itemListAll:
                itemss = {}
                itemss['itemName'] = items.ItemName
                itemss['quantity'] = items.Quantity
                itemss['comment'] = items.Comments
                itemss['userName'] = items.Username
                allItems.append(itemss)
            return jsonify(items=allItems)
        else:
            return jsonify(message="No items in the list")
    else:
        return jsonify(message="List not found")


@app.route('/api/viewList/<grocery_list>', methods=['GET'])
@token_required
def viewList(current_user, grocery_list):
    groupList = GroceryList.query.filter_by(list_id=current_user.groceryList).all()
    itemListAll = Item.query.filter_by().all()
    output = []
    allItems = []
    if groupList:
        if itemListAll:
            for items in itemListAll:
                itemss = {}
                itemss['itemName'] = items.ItemName
                itemss['quantity'] = items.Quantity
                itemss['comment'] = items.Comments
                itemss['userName'] = items.Username
                itemss['id'] = items.item_id
                allItems.append(itemss)
            return jsonify(items=allItems)
        else:
            return jsonify(message="No items in the list")
    else:
        return jsonify(message="List not found")


@app.route('/api/addtoList/<name>/<quanitity>/<comments>')
@token_required
def addtoList(current_user, name, quanitity, comments):
    new = request.form
    print(current_user.firstName)
    newItem = Item(
        Username=current_user.firstName,
        list_id=current_user.groceryList,
        item_id=str(uuid.uuid4()),
        ItemName=name,
        Quantity=quanitity,
        Comments=comments.replace('_', ' ')
    )
    db.session.add(newItem)
    db.session.commit()
    return redirect(url_for('viewListData'))




@app.route('/api/picked', methods=['GET'])
@token_required
def volunteer(current_user):
    data = {}
    data['name'] = current_user.firstName
    groupList = GroceryList.query.filter_by(list_id=current_user.groceryList).first()
    groupList.picked = True
    groupList.userPickerUp = data['name']
    db.session.commit()
    return redirect(url_for('viewListData'))

@app.route('/api/pickedundo', methods=['GET'])
@token_required
def volunteerUndo(current_user):
    data = {}
    data['name'] = current_user.firstName
    groupList = GroceryList.query.filter_by(list_id=current_user.groceryList).first()
    groupList.picked = False
    groupList.userPickerUp = "none"
    db.session.commit()
    return redirect(url_for('viewListData'))


@app.route('/api/removeFromList/<itemid>')
@token_required
def removeFromList(current_user, itemid):
    removeItem = Item.query.filter_by(list_id=current_user.groceryList, item_id=itemid).first()

    if removeItem:
        db.session.delete(removeItem)
        db.session.commit()
        return redirect(url_for('viewListData'))
    else:
        return jsonify(message="Item does not exist")


@app.route('/api/emailInvite/<email>')
@token_required
def emailInvite(current_user,email):
   from_email = Email("demetersgrocery@gmail.com")
   to_email=To(email)
   subject="Verify your email"
   token = s.dumps(email, salt='email-confirm')
   content=Content("text/plain", f"Your friend, {current_user.firstName} is inviting you to join a Demeter's grocery list with the link of http://127.0.0.1:5000/api/addUsertoList/{current_user.groceryList}")
   mail = Mail(from_email, to_email, subject, content)

   response = sg.client.mail.send.post(request_body=mail.get())
   print(response.status_code)
   print(response.body)
   print(response.headers)

   return jsonify(message="Email invite sent")


@app.route('/api/gotItems', methods=['GET'])
@token_required
def gotItems(current_user):
    current_user.groceryList = None
    db.session.commit()
    return redirect(url_for('viewListData'))


@app.route('/api/getGroceryList', methods=['GET'])
@token_required
def viewListData(current_user):
    groupList = GroceryList.query.filter_by(list_id=current_user.groceryList).first()

    user_data = {}
    user_data['firstName'] = current_user.firstName
    user_data['lastName'] = current_user.lastName
    user_data['email'] = current_user.email
    user_data['phoneNumber'] = current_user.phoneNumber
    session['userData'] = user_data

    if groupList:
        list_data = {}
        list_data['list_id'] = groupList.list_id
        list_data['GroceryName'] = groupList.GroceryName
        list_data['date'] = groupList.dateCreated
        list_data['picked'] = groupList.picked
        list_data['pickerUser'] = groupList.userPickerUp

        users = User.query.filter_by(groceryList=current_user.groceryList).all()

        names_data = []

        for x in range(len(users)):
            names_data.append(users[x].firstName)



        groupList = GroceryList.query.filter_by(list_id=current_user.groceryList).all()
        itemListAll = Item.query.filter_by().all()
        output = []
        allItems = []
        if groupList:
            if itemListAll:
                for items in itemListAll:
                    itemss = {}
                    itemss['itemName'] = items.ItemName
                    itemss['quantity'] = items.Quantity
                    itemss['comment'] = items.Comments
                    itemss['userName'] = items.Username
                    itemss['id'] = items.item_id
                    allItems.append(itemss)

                size = len(allItems)
                print(size)
                print(allItems)
                return render_template('dashboard.jinja2', list_data=list_data, names_data=names_data, total=len(users), allItems=allItems, size=size, userdata=session['userData'])
            else:
                size = len(allItems)
                return render_template('dashboard.jinja2', list_data=list_data, names_data=names_data, total=len(users), allItems=allItems, size=size, userdata=session['userData'])
        else:
            return jsonify(message="List not found")








        #return jsonify(list_data=list_data)
    else:
        return redirect(url_for('createList'))


@app.route('/api/getGroceryList', methods=['POST'])
@token_required
def submitData(current_user):
    user_data = {}
    user_data['public_id'] = current_user.public_id

    form = request.form

    if request.form.get('ItemName'):
        item = form['ItemName']
        quantity = form['Quantity']
        comments = form['Comments']
        commentsSend = comments.replace(' ', '_')
        return redirect('/api/addtoList/' + item + "/" + quantity + "/" + commentsSend)
    elif request.form.get('emailFriend'):
        email = form['emailFriend']

        return redirect('/api/emailInvite/' + email)


@app.route('/api/getUser', methods=['GET'])
@token_required
def user(current_user):
    user_data = {}
    user_data['firstName'] = current_user.firstName
    user_data['lastName'] = current_user.lastName
    user_data['email'] = current_user.email
    user_data['groceryList'] = current_user.groceryList

    return jsonify(message=user_data)


@app.route('/api/register', methods=['POST'])
def register():
    data=request.form
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
        return redirect(url_for('login_page'))
        #return jsonify(message='User Created'),201



@app.route('/api/login', methods=['POST'])
def login():
    login=request.form

    user=User.query.filter_by(email=login['email']).first()

    if not user:
        return jsonify(message='A user with this email does not exist.')
    if check_password_hash(user.password,login['password']):
        token = jwt.encode({'public_id': user.public_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
        session['token'] = token
        redir = redirect(url_for('viewListData'))
        redir.headers['x-access-tokens'] = token

        return redir
    else:
        return jsonify(message='Your email or password is incorrect'),401

@app.route('/api/register')

@app.route('/api/register')
def register_page():
    return render_template('register.jinja2')

@app.route('/api/login')
def login_page():
    return render_template('login.jinja2')

@app.route('/api/profile')
@token_required
def profile(current_user):
    return render_template('profile.jinja2', userdata=session['userData'])

@app.route('/api/logout')
@token_required
def logout(current_user):
    session.pop('token', None)
    session.pop('userData', None)
    return redirect(url_for('homepage'))

@app.route('/')
def homepage():
    return render_template('landing.jinja2')

@app.route('/about')
def aboutpage():
    return render_template('about.jinja2')


if __name__ == '__main__':
    app.run(debug=True)