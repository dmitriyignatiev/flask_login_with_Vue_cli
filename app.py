from flask import Flask, render_template,  redirect, flash, url_for
from flask_sqlalchemy import SQLAlchemy
import os
from flask_login import LoginManager, UserMixin, \
                                login_required, login_user, logout_user 

from werkzeug.security import generate_password_hash, check_password_hash

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField


app = Flask(__name__)
app.config['SECRET_KEY']='123'
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URI') or 'mysql+pymysql://root:root@localhost:5883/vue_login?charset=utf8mb4'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db=SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"



@app.route('/')
def index():
    return render_template('base.html')


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200))
                        
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Check hashed password."""
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return '<User %r>' % self.username

@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))

class LoginForm(FlaskForm):
    username = StringField('Username')
    password = PasswordField('Password')
    submit = SubmitField('Sign In')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user=User.query.filter_by(username=form.username.data).first()
        if user is None:
            flash('invalid username')
            return redirect(url_for('login'))
        login_user(user)
        return redirect('/index')
        
    return render_template('login.html', form=form)

@app.route('/index')
@login_required
def index_start():
    return render_template('index.html')
    
    
if __name__=='__main__':
    app.run(host='127.0.0.5', port=5000)