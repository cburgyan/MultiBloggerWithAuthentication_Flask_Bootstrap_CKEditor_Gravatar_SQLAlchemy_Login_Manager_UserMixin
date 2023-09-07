from flask import Flask, render_template, redirect, url_for, flash, abort, request
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, CommentForm, ContactForm, ContactPrePopulatedForm
from flask_gravatar import Gravatar
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired
from functools import wraps
import smtplib
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
MY_EMAIL = os.environ.get('MY_EMAIL')
MY_PASSWORD = os.environ.get('MY_PASSWORD')
ADMIN_ID = os.environ.get('ADMIN_ID')
ckeditor = CKEditor(app)
gravatar = Gravatar(
    app,
    size=100,
    rating='g',
    default='retro',
    force_default=False,
    force_lower=False,
    use_ssl=False,
    base_url=None
)
Bootstrap(app)


# #CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///blog.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager(app)


# #CONFIGURE TABLES

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    #author = db.Column(db.String(250), nullable=False)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

    # Create Foreign Key. In "users.id", the "users" refers to the __tablename__ of User.
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))

    # Create reference to the User object, the "posts" refers to the posts property in the User class.
    author = relationship('User', back_populates='posts')

    # This will act like a list of Comment objects attached to each BlogPost.
    # The "blog_post" refers to the blog_post property in the Comment class.
    comments = relationship('Comment', back_populates='blog_post')


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    is_active = db.Column(db.Boolean, nullable=False)
    is_authenticated = db.Column(db.Boolean, nullable=False)
    is_anonymous = db.Column(db.Boolean, nullable=False)

    # This will act like a list of BlogPost objects attached to each User.
    # The "author" refers to the author property in the BlogPost class.
    posts = relationship('BlogPost', back_populates='author')

    # This will act like a list of Comment objects attached to each User.
    # The "commenter" refers to the commenter property in the Comment class.
    comments = relationship('Comment', back_populates='commenter')

    def get_id(self):
        return str(self.id)


class Comment(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String, nullable=False)

    # Create Foreign Key. In "users.id", the "users" refers to the __tablename__ of User.
    commenter_id = db.Column(db.Integer, db.ForeignKey('users.id'))

    # Create reference to the User object, the "comments" refers to the comments property in the User class.
    commenter = relationship('User', back_populates='comments')

    # Create Foreign Key. In "blog_posts.id", the "blog_posts" refers to the __tablename__ of BlogPost.
    blog_post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))

    # Create reference to the User object, the "comments" refers to the comments property in the User class.
    blog_post = relationship('BlogPost', back_populates='comments')


db.create_all()


class RegisterForm(FlaskForm):
    name = StringField('Username: ', validators=[DataRequired()])
    email = StringField('Email: ', validators=[DataRequired()])
    password = PasswordField('Password: ', validators=[DataRequired()])
    submit = SubmitField('Sign Me Up!')


class LoginForm(FlaskForm):
    email = StringField('Email: ', validators=[DataRequired()])
    password = PasswordField('Password: ', validators=[DataRequired()])
    submit = SubmitField('Submit')


def send_message(email, phone, message, name='None'):
    try:
        with smtplib.SMTP("smtp.mail.yahoo.com", port=587) as smtp_connection:
            smtp_connection.starttls()
            smtp_connection.login(user=MY_EMAIL, password=MY_PASSWORD)
            smtp_connection.sendmail(from_addr=MY_EMAIL,
                                     to_addrs=MY_EMAIL,
                                     msg=f"Subject: From AFTERNOON-CUPS\n\nName:\n{name}\nPhone:\n{phone}\nEmail:\n{email}\nMessage:\n{message}")
    except Exception as error_message:
        print(f"Something Went Wrong In Sending The Email:\n{error_message}")


@login_manager.user_loader
def load_user(user_id):
    return User.query.filter_by(id=user_id).first()


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=['Get', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        name = form.name.data
        email = str(form.email.data).lower()
        old_user = User.query.filter_by(email=email).first()
        if old_user:
            flash(f"You've already signed up with that email, log in instead.")
            return redirect(url_for('login'))
        new_user = User(
            name=name,
            email=email,
            password=generate_password_hash(form.password.data, method='pbkdf2:sha256', salt_length=8),
            is_active=True,
            is_authenticated=True,
            is_anonymous=False
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        print('Registration succeeded.')
        flash(f"{name}, you have successfully registered!")
        return redirect(url_for('get_all_posts'))
    return render_template("register.html", form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = str(form.email.data).lower()
        password = form.password.data
        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                login_user(user)
                db.session.commit()
                flash(f"{user.name}, you have logged in successfully!")
                return redirect(url_for('get_all_posts'))
            else:
                flash(f"Password incorrect. Please try again.")
        else:
            flash(f"The email, {email}, does not exist in our database. Please try again.")
    return render_template("login.html", form=form)


@app.route('/logout')
@login_required
def logout():
    name = current_user.name
    logout_user()
    flash(f"{name} has logged out.")
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    form = CommentForm()
    if form.validate_on_submit():
        if not current_user or not current_user.is_authenticated:
            flash('You need to log in or register to comment.')
            return redirect(url_for('login'))
        else:
            commenter = current_user
            text = form.body.data
            new_comment = Comment(
                commenter=commenter,
                text=text,
                blog_post=requested_post
            )
            db.session.add(new_comment)
            db.session.commit()
            return redirect(url_for('show_post', post_id=post_id))

    admin_pass = 0
    if current_user.is_authenticated:
        admin_pass = current_user.id == ADMIN_ID or check_password_hash(current_user.password,
                                                                 os.environ.get('ADMIN_PASSWORD'))
    return render_template("post.html", post=requested_post, form=form, admin_pass=admin_pass)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact", methods=['GET', 'POST'])
def contact():
    if current_user.is_authenticated:
        form = ContactPrePopulatedForm()
    else:
        form = ContactForm()

    if form.validate_on_submit():
        if current_user.is_authenticated:
            name = current_user.name
            email = current_user.email
        else:
            email = form.email.data
            name = form.name.data
        phone = form.phone.data
        message = form.message.data
        send_message(email, phone, message, name)

        flash('Message sent!')
        return redirect(url_for('contact'))

    return render_template("contact.html", form=form)


# Allows only the admin or the poster of a post to access the particular route that the
# function decorator decorates
def admin_or_post_author_only(func):
    @wraps(func)
    def wrapper_func(*args, **kwargs):
        post_id = kwargs.get('post_id')
        if post_id:
            post_author_id = BlogPost.query.filter_by(id=post_id).first().author.id
            if hasattr(current_user, 'id') and (post_author_id == current_user.id or
                                                current_user.id == ADMIN_ID or
                                                check_password_hash(current_user.password,
                                                                    os.environ.get('ADMIN_PASSWORD'))):
                return func(*args, **kwargs)
            else:
                return abort(403)
        else:
            print('Something went wrong. This line should not be reached.')
            return abort(500)
    return wrapper_func


@app.route("/new-post", methods=['GET', 'POST'])
@login_required
def add_new_post():
    form = CreatePostForm(body="Photo by (don't forget to credit your photo/image (eg 'Photo by John Smith') here)")
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=['POST', 'GET'])
@admin_or_post_author_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_or_post_author_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route('/author/<author_name>')
def author_page(author_name):
    author_id = request.args.get('author_id')
    user = User.query.get(author_id)
    posts = user.posts

    admin_pass = 0
    if current_user.is_authenticated:
        admin_pass = current_user.id == ADMIN_ID or check_password_hash(current_user.password,
                                                                 os.environ.get('ADMIN_PASSWORD'))
    return render_template('author.html', author=user, authors_posts=posts, admin_pass = admin_pass)


def admin_or_author_only(func):
    @wraps(func)
    def wrapper_func(*args, **kwargs):
        author_id = int(kwargs.get('author_id'))
        if author_id:
            # post_author_id = BlogPost.query.filter_by(id=post_id).first().author.id
            if hasattr(current_user, 'id') and (current_user.id == author_id or current_user.id == ADMIN_ID
                                                or check_password_hash(current_user.password,
                                                                       os.environ.get('ADMIN_PASSWORD'))):
                return func(*args, **kwargs)
            else:
                return abort(403)
        else:
            print('No, such author is in the database.')
            return abort(403)
    return wrapper_func


@app.route('/author/comments/<author_name>/<author_id>')
@admin_or_author_only
def author_comments_page(author_name, author_id):
    user = User.query.get(author_id)
    comments = user.comments
    if comments:
        return render_template('comments.html', author=user, authors_comments=comments)
    flash('The server did not find any comments.')
    posts = user.posts
    return render_template('author.html', author=user, authors_posts=posts)


if __name__ == "__main__":
    app.run(debug=True)#host='0.0.0.0', port=5000)
