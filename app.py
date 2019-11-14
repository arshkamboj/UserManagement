from flaskApp import app
from db_config import db
from flask_login import LoginManager, login_user , logout_user , current_user , login_required
from flask import jsonify, render_template, flash, request, session, request, flash, url_for, redirect, render_template, abort ,g,make_response,flash
from werkzeug import generate_password_hash, check_password_hash
from flask_marshmallow import Marshmallow 
import jwt
import datetime
from functools import wraps
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm 
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
bootstrap = Bootstrap(app)
#import pdb; # Init ma

ma = Marshmallow(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class LoginForm(FlaskForm):
    inputEmail = StringField('inputEmail', validators=[InputRequired(), Length(min=4, max=15)])
    inputPassword = PasswordField('inputPassword', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('remember me')

class RegisterForm(FlaskForm):
    inputEmail = StringField('inputEmail', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    inputName = StringField('inputName', validators=[InputRequired(), Length(min=4, max=15)])
    inputPassword = PasswordField('inputPassword', validators=[InputRequired(), Length(min=8, max=80)])
    inputCPassword = PasswordField('inputCPassword', validators=[InputRequired(), Length(min=8, max=80)])


# user Schema
class UserSchema(ma.Schema):
  class Meta:
    fields = ('user_id', 'user_name', 'user_email', 'user_password')

# Init schema
user_schema = UserSchema()
users_schema = UserSchema(many=True)

class ToDoSchema(ma.Schema):
  class Meta:
    fields = ('todo_id', 'todo_text', 'is_complete', 'user_id')


# Init schema
todo_schema = ToDoSchema()
todos_schema = ToDoSchema(many=True)

@app.route('/')
def main():
    return render_template('index.html')    

#@app.route('/showSignUp')
#def showSignUp():
    #return render_template('signup.html')

#@app.route('/showSignIn')
#def showSignIn():
    #return render_template('signin.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', name=current_user.user_name)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('main')) 

class tbl_toDoList(db.Model):
    __tablename__='tbl_toDoList'
    todo_id = db.Column(db.Integer, primary_key=True)
    todo_text = db.Column(db.String(50))
    is_complete = db.Column(db.Boolean)
    user_id=db.Column(db.Integer)

    def __init__(self, todo_text, is_complete,user_id):
        self.todo_text = todo_text
        self.is_complete = is_complete
        self.user_id = user_id

class tbl_user(db.Model):
    __tablename__='tbl_user'
    user_id = db.Column(db.Integer, primary_key=True)
    user_name = db.Column(db.String(40))
    user_email = db.Column(db.String(40))
    user_password = db.Column(db.String(255))

    def __init__(self, user_name, user_email,user_password):
        self.user_name = user_name
        self.user_email = user_email
        self.user_password=user_password

    def is_authenticated(self):
        return True
 
    def is_active(self):
        return True
 
    def is_anonymous(self):
        return False
 
    def get_id(self):
        return unicode(self.user_id)
 
    def __repr__(self):
        return '<User %r>' % (self.user_name)

    # Class method which finds user from DB by username
    @classmethod
    def find_user_by_username(cls, user_name):
        return cls.query.filter_by(user_name=user_name).first()
    # Class method which finds user from DB by id
    @classmethod
    def find_user_by_id(cls, user_id):
        return cls.query.filter_by(user_id=user_id).first()

    # Method to save user to DB
    def save_to_db(self):
        db.session.add(self)
        db.session.commit()
    # Method to remove user from DB
    def remove_from_db(self):
        db.session.delete(self)
        db.session.commit()


@login_manager.user_loader
def load_user(user_id):
    return tbl_user.query.get(int(user_id))

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message' : 'Token is missing!'}), 401

        try: 
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = tbl_user.query.filter_by(user_id=data['user_id']).first()
        except:
            return jsonify({'message' : 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated


@app.route('/signup', methods=['GET','POST'])
def signup():
    form = RegisterForm()
    # read the posted values from the UI
    #_json = request.json
    #_name = _json['inputName']
    #_email = _json['inputEmail']
    #_password = _json['inputPassword']
    #_name = request.form['inputName']
    #_email = request.form['inputEmail']
    #_password = request.form['inputPassword']

    if form.validate_on_submit():
        _hashed_password = generate_password_hash(form.inputPassword.data, method='sha256')
        new_user=tbl_user(user_name=form.inputName.data, user_email=form.inputEmail.data, user_password=_hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return user_schema.jsonify(new_user)
    return render_template('signup.html', form=form)

@app.route('/users')
@token_required
def users(current_user):
    all_users=tbl_user.query.all()
    result = users_schema.dump(all_users)
    return jsonify(result)

@app.route('/signin',methods=['GET','POST'])
def singIn():
    #auth = request.authorization
    #_json = request.json
    #_email = _json['inputEmail']
    #_password = _json['inputPassword']
    #_email = request.form['inputEmail']
    #_password = request.form['inputPassword']
    #if not _email or not _password:
    #    flash("email id or password is missing")
    #    return redirect(url_for('showSignIn'))

    form = LoginForm()

    if form.validate_on_submit():
        user = tbl_user.query.filter_by(user_email=form.inputEmail.data).first()
        if user:
            if check_password_hash(user.user_password, form.inputPassword.data):
                token = jwt.encode({'user_id' : user.user_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
                #login_user(user, remember=form.remember.data)
                return render_template('dashboard.html')
                #return redirect(url_for('dashboard'))

        return '<h1>Invalid username or password</h1>'
        #return '<h1>' + form.username.data + ' ' + form.password.data + '</h1>'

    return render_template('signin.html', form=form)

    #user = tbl_user.query.filter_by(user_email=_email).first()

    #if not user:
        #flash("email doesn't exist")
        #return redirect(url_for('showSignUp'))

    #if check_password_hash(user.user_password, _password):
        #token = jwt.encode({'user_id' : user.user_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
        #return jsonify({'token':token.decode()})

        #return render_template('dashboard.html')

    #flash("Password is incorrect")
    
    #return redirect(url_for('showSignIn'))



@app.route('/user/<id>')
@token_required
def user(current_user,id):
    _id=id;
    result=tbl_user.query.get(_id)
    if not result:
        return jsonify({"message":"no user found"})
    return user_schema.jsonify(result)




@app.route('/update/<id>', methods=['PUT'])
@token_required
def update_user(current_user,id):
    user=tbl_user.query.get(id)
    if not user:
        return jsonify({"message":"User not found. Failed to update the user"})
    _json = request.json
    _name = _json['inputName']
    _email = _json['inputEmail']
    _password = _json['inputPassword']
    _hashed_password = generate_password_hash(_password)
    user.user_name=_name
    user.user_email=_email
    user.user_password=_hashed_password
    db.session.commit()
    return user_schema.jsonify(user)


@app.route('/delete/<id>',methods=['DELETE'])
@token_required
def delete_user(current_user,id):
    user = tbl_user.query.get(id)
    if not user:
        return jsonify({"message":"User not found. Failed to delete the user"})
    db.session.delete(user)
    db.session.commit()
    return user_schema.jsonify(user)

@app.route('/todo', methods=['GET'])
@token_required
def get_all_todos(current_user):
    all_todos=tbl_toDoList.query.all()
    result = todos_schema.dump(all_todos)
    return jsonify(result)

@app.route('/todo/<todo_id>', methods=['GET'])
@token_required
def get_one_todo(current_user, todo_id):
    result=tbl_toDoList.query.get(todo_id)
    if not result:
        return jsonify({"message":"no to dos found"})
    return todo_schema.jsonify(result)

@app.route('/todo/add', methods=['POST'])
@token_required
def create_todo(current_user):
    _json = request.json
    _text = _json['inputText']
    _complete = _json['inputComplete']
    #_name = request.form['inputName']
    #_email = request.form['inputEmail']
    #_password = request.form['inputPassword']
    new_todo=tbl_toDoList(_text,_complete,user_id=current_user.user_id)
    db.session.add(new_todo)
    db.session.commit()
    return todo_schema.jsonify(new_todo)

@app.route('/todo/<todo_id>', methods=['PUT'])
@token_required
def complete_todo(current_user, todo_id):
    todo = tbl_toDoList.query.filter_by(id=todo_id, user_id=current_user.id).first()

    if not todo:
        return jsonify({'message' : 'No todo found!'})

    todo.complete = True
    db.session.commit()

    return jsonify({'message' : 'Todo item has been completed!'})

@app.route('/todo/<todo_id>', methods=['DELETE'])
@token_required
def delete_todo(current_user, todo_id):
    todo = tbl_toDoList.query.filter_by(id=todo_id, user_id=current_user.id).first()

    if not todo:
        return jsonify({'message' : 'No todo found!'})

    db.session.delete(todo)
    db.session.commit()

    return jsonify({'message' : 'Todo item deleted!'})


@app.errorhandler(404)
def not_found(error=None):
    message = {
        'status': 404,
        'message': 'Not Found: ' + request.url,
    }
    resp = jsonify(message)
    resp.status_code = 404
    return resp

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5004,debug=True)