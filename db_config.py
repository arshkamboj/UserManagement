from flask_sqlalchemy import SQLAlchemy
from flaskApp import app
 
# MySQL configurations
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:root@localhost:3306/users'
app.config['SQLALCHEMY_TRACK_MODIFICATION'] = False
app.config['SECRET_KEY']='mysecretkey'
db = SQLAlchemy(app)

