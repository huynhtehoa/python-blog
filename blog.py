from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, ValidationError, TextAreaField
from wtforms.validators import DataRequired, Email, EqualTo, Length
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, current_user, login_required, logout_user, LoginManager, UserMixin
from datetime import datetime

app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
app.config["SECRET_KEY"] = "so secret that i dont even know what my secret key is"

db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.init_app(app)
login_manager.login_view = "login"

# help login manager get info about user
@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(user_id)


class Users(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False, unique=True)
    email = db.Column(db.String(255), nullable=False, unique=True)
    password = db.Column(db.String(120), nullable=False)

    # hash password
    def set_password(self, password):
        self.password = generate_password_hash(password)

    # check if passwords are the same
    def check_password(self, password):
        return check_password_hash(self.password, password)


db.create_all()


class Blogs(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    body = db.Column(db.String(), nullable=False)
    author_name = db.Column(db.String(80), nullable=False)
    created_on = db.Column(db.DateTime)
    updated_on = db.Column(db.DateTime)


db.create_all()


class RegistrationForm(FlaskForm):
    username = StringField("Username", validators=[
                           DataRequired(), Length(min=3, max=79)])
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[
                             DataRequired(), EqualTo("pass_confirm")])
    pass_confirm = PasswordField(
        "Confirm Password", validators=[DataRequired()])
    submit = SubmitField("Register")

    # Using function to validate username
    def validate_username(self, field):
        if Users.query.filter_by(username=field.data).first():
            flash("Existed username")
            raise ValidationError("Existed Username")

    # Using function to validate email
    def validate_email(self, field):
        if Users.query.filter_by(email=field.data).first():
            flash("Existed email")
            raise ValidationError("Existed Email")


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")


class BlogForm(FlaskForm):
    title = StringField("Title", validators=[
                        DataRequired(), Length(min=3, max=150)])
    body = TextAreaField("Body", validators=[DataRequired()])
    submit = SubmitField("Create")


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/register", methods=["POST", "GET"])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        # create user
        new_user = Users(username=form.username.data,
                         email=form.email.data)
        new_user.set_password(form.password.data)

        db.session.add(new_user)
        db.session.commit()
        # looking for login() function and redirect to its route
        return redirect(url_for("login"))

    return render_template("register.html", form=form)


@app.route("/login", methods=["POST", "GET"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        log_user = Users.query.filter_by(username=form.username.data).first()
        # check if username exists
        if log_user is None:
            flash("Invalid Username")
            return redirect(url_for("login"))

        # if username is correct
        if not log_user.check_password(form.password.data):
            # Handle passsword is not correct
            flash("Incorrect password")
            return redirect(url_for("login"))

    # we have the correct username and password
        login_user(log_user)
        return redirect(url_for("welcome"))

    return render_template("login.html", form=form)


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("index"))


@app.route("/welcome")
@login_required
def welcome():
    return render_template("welcome.html")


@app.route("/create", methods=["POST", "GET"])
@login_required
def create():
    form = BlogForm()
    if form.validate_on_submit():
        author_name = current_user.username
        create = datetime.now()
        new_post = Blogs(title=form.title.data,
                         body=form.body.data,
                         author_name=author_name,
                         created_on=create)
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("posts"))

    return render_template("create.html", form=form)


@app.route("/posts")
def posts():
    posts = Blogs.query.all()
    return render_template("posts.html", posts=posts)


@app.route("/update/<post_id>", methods=["POST", "GET"])
@login_required
def update(post_id):
    post = Blogs.query.filter_by(id=post_id).first()
    form = BlogForm()
    form.title.data = post.title
    form.body.data = post.body
    if current_user.username != post.author_name:
        flash("You are not the owner of this post")
        return redirect(url_for("posts"))
    if form.validate_on_submit():
        post.title = form.title.data
        post.body = form.body.data
        post.updated_on = datetime.now()
        db.session.commit()
        return redirect(url_for("posts"))
    return render_template("update.html", form=form)


@app.route("/delete/<post_id>", methods=["POST", "GET"])
@login_required
def delete(post_id):
    post = Blogs.query.filter_by(id=post_id).first()
    form = BlogForm()

    if current_user.username != post.author_name:
        flash("You are not the owner of this post")
        return redirect(url_for("posts"))

    db.session.delete(post)
    db.session.commit()
    return redirect(url_for("posts"))


if __name__ == "__main__":
    app.run(debug=True)
