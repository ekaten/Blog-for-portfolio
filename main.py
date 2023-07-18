from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, CommentForm
from flask_gravatar import Gravatar
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, Email
from functools import wraps




# decorator function for admin access only#Create admin-only decorator
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        #If id is not 1 then return abort with 403 error
        if current_user.id != 1:
            return abort(403)
        #Otherwise continue with the route function
        return f(*args, **kwargs)
    return decorated_function

app = Flask(__name__)
app.secret_key = "skdkkdfkksdjfkljskdfj"
ckeditor = CKEditor(app)
app.config['CKEDITOR_PKG_TYPE'] = 'basic'
Bootstrap(app)
login_manager = LoginManager()
login_manager.init_app(app)
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)



# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


# Create a user class (user table in the db)
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(1000))
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    # relational for posts
    posts = relationship('BlogPost', back_populates="author")
    # relational for comments
    comments = relationship('CommentSection', back_populates="author")


# CONFIGURE BlogPosts TABLES
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    # Relational for authors
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    author = relationship("User", back_populates="posts")
    # Relational for comments
    comments = relationship('CommentSection', back_populates="post")
    # data
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)


# Configure a COMENTS table
class CommentSection(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    # relational for authors
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    author = relationship("User", back_populates="comments")
    # relational for posts
    post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))
    post = relationship("BlogPost", back_populates="comments")
    # Data field
    text = db.Column(db.Text, nullable=False)


db.create_all()

# User loader callback
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# User register form
class RegisterForm(FlaskForm):
    email = StringField(label='Email', validators=[DataRequired(), Email()])
    password = PasswordField(label='Password', validators=[DataRequired(), Length(min=6)])
    name = StringField(label='Name', validators=[DataRequired()])
    register = SubmitField('Register')


# User login form
class LoginForm(FlaskForm):
    email = StringField(label='Email', validators=[DataRequired()])
    password = PasswordField(label='Password', validators=[DataRequired()])
    login = SubmitField(label="Log In")




@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts, logged_in=current_user.is_authenticated, current_user=current_user)



@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if request.method == "GET":
        print("RENDER REGISTER FORM")
        return render_template("register.html", form=form, logged_in=current_user.is_authenticated)

    if form.validate_on_submit():
        email = form.email.data
        if User.query.filter_by(email=email).first():
            flash("A user with this email already exists. Please, log in instead")
            return redirect(url_for('login'))
        password = generate_password_hash(form.password.data, "pbkdf2:sha256", salt_length=8)
        name = form.name.data
        new_user = User(email=email, password=password, name=name)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        print("USER CREATED")
        return redirect('/')



@app.route('/login', methods=["POST", "GET"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        user = User.query.filter_by(email=email).first()
        if not user:
            flash("User doesn't exist. Please, register")
            print("NO USER")
            return redirect(url_for('register'))
        if check_password_hash(user.password, password):
            print('CORRECT')
            login_user(user)
            return redirect('/')
        else:
            flash("Incorrect Password. Please, try again")
            print('NO MATCH')
            return redirect(url_for('login'))


    else:
        print("REDIRECTED TO LOGIN")
        return render_template("login.html", form=form,  logged_in=current_user.is_authenticated)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    form = CommentForm()
    requested_post = BlogPost.query.get(post_id)
    comments = CommentSection.query.filter_by(post_id=requested_post.id).all()
    if form.validate_on_submit():
        if current_user.is_authenticated:
            new_comment = CommentSection(
                text=form.comment.data,
                author=current_user,
                post=requested_post
            )
            db.session.add(new_comment)
            db.session.commit()
            return redirect(url_for('show_post', post_id=requested_post.id))
        else:
            flash("Please, log in to leave a comment.")
            return redirect(url_for('login'))
    return render_template("post.html", post=requested_post, logged_in=current_user.is_authenticated, current_user=current_user, form=form, comments=comments)


@app.route("/about")
def about():
    return render_template("about.html", logged_in=current_user.is_authenticated)


@app.route("/contact")
def contact():
    return render_template("contact.html", logged_in=current_user.is_authenticated)


@app.route("/new-post", methods=["GET", "POST"])
# @admin_only
def add_new_post():
    form = CreatePostForm()
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
    return render_template("make-post.html", form=form, logged_in=current_user.is_authenticated)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@login_required
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, logged_in=current_user.is_authenticated)


@app.route("/delete/<int:post_id>")
@login_required
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(host='0.0.0.0', debug=True)
