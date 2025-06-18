import os

from flask import Flask, render_template, request, flash, redirect, session, g, url_for
# from flask_debugtoolbar import DebugToolbarExtension
from sqlalchemy.exc import IntegrityError
from flask_migrate import Migrate
from forms import UserAddForm, LoginForm, MessageForm, UserEditForm, ResendConfirmationForm, PasswordResetForm, PasswordResetRequestForm
from models import db, connect_db, User, Message, Likes, Report
from flask_mail import Mail, Message as MailMessage
from itsdangerous import URLSafeTimedSerializer
from werkzeug.security import check_password_hash
from dotenv import load_dotenv
from flask_bcrypt import Bcrypt
from flask_login import login_user, LoginManager, current_user, logout_user
from utils import save_image, generate_reset_token, verify_reset_token



load_dotenv()
bcrypt = Bcrypt()

from flask_login import LoginManager




CURR_USER_KEY = "curr_user"

app = Flask(__name__)

# Get DB_URI from environ variable (useful for production/testing) or,
# if not set there, use development local db.
app.config['SQLALCHEMY_DATABASE_URI'] = (
    os.environ.get('DATABASE_URL', 'postgresql:///squawk'))

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ECHO'] = False
app.config['DEBUG_TB_INTERCEPT_REDIRECTS'] = True
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

# toolbar = DebugToolbarExtension(app)


# Email configuration
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT'))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS') == 'True'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')

mail = Mail(app)

# Create a serializer for generating and verifying tokens
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])


# Initialize Flask-Migrate
migrate = Migrate(app, db)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

# Set the login view (redirects users to this view if they are not logged in)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    """Load user by ID."""
    return User.query.get(int(user_id))

@app.before_request
def add_user_to_g():
    """If we're logged in, add current user to Flask global."""
    print(f"current_user: {current_user}")  # Debugging
    if current_user.is_authenticated:
        g.user = current_user
        print(f"g.user set to: {g.user}")  # Debugging
    else:
        g.user = None
        print("g.user set to None")  # Debugging

connect_db(app)

with app.app_context():
    print("Message model:", Message)
    print("Message.query:", Message.query)
    db.create_all()





##############################################################################
# User signup/login/logout

#Function to send confiration email
def send_confirmation_email(user_email):
    token = serializer.dumps(user_email, salt='email-confirmation-salt')
    confirm_url = url_for('confirm_email', token=token, _external=True)

    msg = MailMessage(
        subject='Confirm Your Account',  # Use `subject` as a keyword argument
        recipients=[user_email],         # Use `recipients` as a keyword argument
        html=render_template('users/confirmation_email.html', confirm_url=confirm_url)
    )
    mail.send(msg)

#route to handle confirmation link
@app.route('/confirm/<token>')
def confirm_email(token):
    try:
        email = serializer.loads(token, salt='email-confirmation-salt', max_age=3600)  # Token valid for 1 hour
        print(f"Email extracted from token: {email}")  # Debugging
    except Exception as e:
        print(f"Token validation error: {e}")  # Debugging
        flash('The confirmation link is invalid or has expired.', 'danger')
        return redirect(url_for('signup'))

    user = User.query.filter_by(email=email).first_or_404()
    print(f"User found: {user}")  # Debugging
    if user.check_confirmation():
        flash('Account already confirmed. Please log in.', 'success')
    else:
        user.is_confirmed = True
        print(f"Before commit: {user.is_confirmed}")  # Debugging
        try:
            db.session.commit()
            print(f"After commit: {user.is_confirmed}")  # Debugging
        except Exception as e:
            print(f"Commit error: {e}")  # Debugging
            flash('An error occurred while confirming your account.', 'danger')
            return redirect(url_for('signup'))
        flash('Your account has been confirmed!', 'success')

    return redirect(url_for('login'))

#route for resending confirmation email
@app.route('/resend-confirmation', methods=['GET', 'POST'])
def resend_confirmation():
    print("Accessed /resend-confirmation route")  # Debugging
    form = ResendConfirmationForm()
    if form.validate_on_submit():
        print("Form validated")  # Debugging
        user = User.query.filter_by(email=form.email.data).first()
        print(f"User found: {user}")  # Debugging
        if user:
            if user.is_confirmed:
                flash('This account is already confirmed. Please log in.', 'success')
                return redirect(url_for('login'))
            send_confirmation_email(user.email)
            flash('A new confirmation email has been sent to your email address.', 'info')
        else:
            flash('No account found with that email address.', 'danger')
        return redirect(url_for('resend_confirmation'))

    return render_template('users/resend_confirmation.html', form=form)


# @app.before_request
# def add_user_to_g():
#     """If we're logged in, add curr user to Flask global."""

#     if CURR_USER_KEY in session:
#         g.user = User.query.get(session[CURR_USER_KEY])

#     else:
#         g.user = None


# def do_login(user):
#     """Log in user."""

#     session[CURR_USER_KEY] = user.id


# def do_logout():
#     """Logout user."""

#     if CURR_USER_KEY in session:
#         del session[CURR_USER_KEY]


@app.route('/signup', methods=["GET", "POST"])
def signup():
    """Handle user signup.

    Create new user and add to DB. Send confirmation email.
    Redirect to login page with a message to confirm the account.

    If form not valid, present form.

    If there already is a user with that username: flash message
    and re-present form.
    """
    if CURR_USER_KEY in session:
        del session[CURR_USER_KEY]
    form = UserAddForm()

    if form.validate_on_submit():
        try:
            user = User.signup(
                username=form.username.data,
                password=form.password.data,
                email=form.email.data,
                image_url=form.image_url.data or User.image_url.default.arg,
            )
            db.session.commit()

            # Send confirmation email
            send_confirmation_email(user.email)
            flash((
                "A confirmation email has been sent to your email address. "
                "If you didn't receive it, check your spam folder, then <a href='/resend-confirmation'>click here</a> to resend the confirmation email."
            ), "info")

            return redirect("/login")

        except IntegrityError:
            flash("Username or email already taken", 'danger')
            return render_template('users/signup.html', form=form)

    return render_template('users/signup.html', form=form)



@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        print("Form validated")  # Debugging
        user = User.query.filter_by(email=form.email.data).first()
        print(f"User found: {user}")  # Debugging
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            print("Password matches")  # Debugging
            if not user.is_confirmed:
                flash('Your account is not confirmed. Please check your email or resend the confirmation email.', 'warning')
                return redirect(url_for('resend_confirmation'))
            login_user(user)
            print(f"User logged in: {user}")  # Debugging
            return redirect(url_for('homepage'))
        flash('Invalid email or password.', 'danger')
    return render_template('users/login.html', form=form)


@app.route('/logout')
def logout():
    """Handle logout of user."""
    logout_user()  # Use Flask-Login's built-in function
    flash("You have successfully logged out", 'success')
    return redirect("/login")

# Admin Dashboard route:

@app.route('/admin', methods=["GET"])
def admin_dashboard():
    """Admin dashboard for managing reports and users."""
    if not current_user.is_authenticated or not current_user.is_admin:
        flash("Access unauthorized.", "danger")
        return redirect('/')

    # Fetch reported messages
    reported_messages = db.session.query(
        Report.id,
        Message.text,
        User.username,
        Report.timestamp
    ).join(Message, Report.message_id == Message.id).join(User, Report.user_id == User.id).all()

    # Fetch all users
    users = User.query.all()

    return render_template('admin/dashboard.html', reported_messages=reported_messages, users=users)

  


##############################################################################
# General user routes:

@app.route('/users')
def list_users():
    """Page with listing of users.

    Can take a 'q' param in querystring to search by that username.
    """

    search = request.args.get('q')

    if not search:
        users = User.query.all()
    else:
        users = User.query.filter(User.username.like(f"%{search}%")).all()

    return render_template('users/index.html', users=users)


@app.route('/users/<int:user_id>')
def users_show(user_id):
    """Show user profile."""

    user = User.query.get_or_404(user_id)

    # snagging messages in order from the database;
    # user.messages won't be in order by default
    messages = (Message
                .query
                .filter(Message.user_id == user_id)
                .order_by(Message.timestamp.desc())
                .limit(100)
                .all())
    likes = [message.id for message in user.likes]
    return render_template('users/show.html', user=user, messages=messages, likes=likes)


@app.route('/users/<int:user_id>/following')
def show_following(user_id):
    """Show list of people this user is following."""

    if not g.user:
        flash("Access unauthorized.", "danger")
        return redirect("/")

    user = User.query.get_or_404(user_id)
    return render_template('users/following.html', user=user)


@app.route('/users/<int:user_id>/followers')
def users_followers(user_id):
    """Show list of followers of this user."""

    if not g.user:
        flash("Access unauthorized.", "danger")
        return redirect("/")

    user = User.query.get_or_404(user_id)
    return render_template('users/followers.html', user=user)


@app.route('/users/follow/<int:follow_id>', methods=['POST'])
def add_follow(follow_id):
    """Add a follow for the currently-logged-in user."""

    if not g.user:
        flash("Access unauthorized.", "danger")
        return redirect("/")

    followed_user = User.query.get_or_404(follow_id)
    g.user.following.append(followed_user)
    db.session.commit()

    return redirect(f"/users/{g.user.id}/following")


@app.route('/users/stop-following/<int:follow_id>', methods=['POST'])
def stop_following(follow_id):
    """Have currently-logged-in-user stop following this user."""

    if not g.user:
        flash("Access unauthorized.", "danger")
        return redirect("/")

    followed_user = User.query.get(follow_id)
    g.user.following.remove(followed_user)
    db.session.commit()

    return redirect(f"/users/{g.user.id}/following")

# routes for "likes"

@app.route('/users/<int:user_id>/likes', methods=["GET"])
def show_likes(user_id):
    if not g.user:
        flash("Access unauthorized", "danger")
        return redirect("/")
    
    user= User.query.get_or_404(user_id)
    return render_template('users/likes.html', user=user, likes=user.likes)

@app.route('/messages/<int:message_id>/like', methods=['POST'])
def add_like(message_id):
    """Toggle a liked message for the currently logged-in user."""

    if not g.user:
        flash("Access unauthorized", "danger")
        return redirect("/")

    liked_message = Message.query.get_or_404(message_id)

    # Prevent users from liking their own messages
    if liked_message.user_id == g.user.id:
        flash("You cannot like your own message.", "danger")
        return abort(403)

    # Toggle like/unlike
    if liked_message in g.user.likes:
        g.user.likes.remove(liked_message)
    else:
        g.user.likes.append(liked_message)

    db.session.commit()

    # Return a 204 No Content response for AJAX requests
    return '', 204


@app.route('/users/profile', methods=["GET", "POST"])
def profile():
    """Update profile for current user."""

    if not current_user.is_authenticated:
        flash("Access unauthorized", "danger")
        return redirect("/")

    user = current_user
    form = UserEditForm(obj=user)

    if form.validate_on_submit():
        user.username = form.username.data
        user.email = form.email.data
        user.bio = form.bio.data
        user.location = form.location.data

        # Normalize social media URLs
        def normalize_url(url):
            if url and not url.startswith("http://") and not url.startswith("https://"):
                return f"https://{url}"
            return url

        user.twitter_url = normalize_url(form.twitter_url.data)
        user.facebook_url = normalize_url(form.facebook_url.data)
        user.linkedin_url = normalize_url(form.linkedin_url.data)

        # Handle image uploads
        if form.image_url.data:
            user.image_url = save_image(form.image_url.data)
        if form.header_image_url.data:
            user.header_image_url = save_image(form.header_image_url.data)

        db.session.commit()
        flash("Profile updated successfully!", "success")
        return redirect(f"/users/{user.id}")

    return render_template('users/edit.html', form=form, user=user)


@app.route('/users/delete', methods=["POST"])
def delete_user():
    """Delete user."""

    if not g.user:
        flash("Access unauthorized.", "danger")
        return redirect("/")

    do_logout()

    db.session.delete(g.user)
    db.session.commit()

    return redirect("/signup")

@app.route('/users/<int:user_id>/likes')
def user_likes(user_id):
    """Show liked warbles for a user."""
    user = User.query.get_or_404(user_id)
    return render_template('users/likes.html', user=user, likes=user.likes)


##############################################################################
# Messages routes:

@app.route('/messages/new', methods=["POST"])
def messages_add():
    """Add a new message (warble)."""

    if not g.user:
        flash("Access unauthorized.", "danger")
        return redirect("/")

    text = request.form["text"]
    if not text:
        flash("Message cannot be empty.", "danger")
        return redirect("/")

    message = Message(text=text, user_id=g.user.id)
    db.session.add(message)
    db.session.commit()

    flash("Warble created!", "success")
    return redirect(f"/users/{g.user.id}")

    # return render_template('messages/new.html', form=form)


@app.route('/messages/<int:message_id>', methods=["GET"])
def messages_show(message_id):
    """Show a message with paginated replies."""
    msg = Message.query.get_or_404(message_id)  # Fetch the parent message
    page = request.args.get('page', 1, type=int)  # Get the current page number
    per_page = 5  # Number of replies per page

    # Paginate replies
    paginated_replies = Message.query.filter_by(parent_id=message_id).paginate(page=page, per_page=per_page)

    return render_template(
        'messages/show.html',
        message=msg,
        replies=paginated_replies
    )


@app.route('/messages/<int:message_id>/delete', methods=["POST"])
def messages_destroy(message_id):
    """Delete a message."""

    if not g.user:
        flash("Access unauthorized.", "danger")
        return redirect("/")

    msg = Message.query.get_or_404(message_id)
    if msg.user_id !=g.user.id:
        flash("Access unauthorized.", "danger")
        return redirect("/")
    
    db.session.delete(msg)
    db.session.commit()

    return redirect(f"/users/{g.user.id}")

@app.route('/messages/<int:message_id>/reply', methods=["POST"])
def reply_to_message(message_id):
    """Reply to a specific message."""
    if not current_user.is_authenticated:
        flash("Access unauthorized.", "danger")
        return redirect('/')

    parent_message = Message.query.get_or_404(message_id)
    text = request.form.get('text')

    if not text:
        flash("Reply cannot be empty.", "danger")
        return redirect(f'/messages/{message_id}')

    reply = Message(
        text=text,
        user_id=current_user.id,
        parent_id=parent_message.id
    )
    db.session.add(reply)
    db.session.commit()
    flash("Reply posted successfully!", "success")
    return redirect(f'/messages/{message_id}')

##############################################################################
# Homepage and error pages


@app.route('/')
def homepage():
    print(f"g.user at homepage: {g.user}")  # Debugging
    print(f"current_user at homepage: {current_user}")  # Debugging
    """Show homepage:

    - anon users: no messages
    - logged in: 100 most recent messages of followed_users
    """

    if g.user:
        following_ids = [f.id for f in g.user.following] + [g.user.id]

        messages = (Message
            .query
            .filter(Message.user_id.in_(following_ids))
            .order_by(Message.timestamp.desc())
            .limit(100)
            .all())
        
        liked_msg_ids = [msg.id for msg in g.user.likes]

        return render_template('home.html', messages=messages, likes=liked_msg_ids)

    else:
        return render_template('home-anon.html')

@app.errorhandler(404)
def page_not_found(e):
    """404 not found page"""
    return render_template('404.html'), 404


##############################################################################
# Turn off all caching in Flask
#   (useful for dev; in production, this kind of stuff is typically
#   handled elsewhere)
#
# https://stackoverflow.com/questions/34066804/disabling-caching-in-flask

@app.after_request
def add_header(req):
    """Add non-caching headers on every request."""

    req.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    req.headers["Pragma"] = "no-cache"
    req.headers["Expires"] = "0"
    req.headers['Cache-Control'] = 'public, max-age=0'
    return req

# Routes for password reset

@app.route('/reset-password', methods=["GET", "POST"])
def reset_password_request():
    """Request a password reset."""
    if current_user.is_authenticated:
        return redirect('/')

    form = PasswordResetRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            send_password_reset_email(user)
        flash("If an account with that email exists, a password reset link has been sent.", "info")
        return redirect('/login')

    return render_template('auth/reset_password_request.html', form=form)


@app.route('/reset-password/<token>', methods=["GET", "POST"])
def reset_password(token):
    """Reset the password."""
    if current_user.is_authenticated:
        return redirect('/')

    user = verify_reset_token(token)
    if not user:
        flash("The password reset link is invalid or has expired.", "danger")
        return redirect('/reset-password')

    form = PasswordResetForm()
    if form.validate_on_submit():
        hashed_pwd = bcrypt.generate_password_hash(form.password.data).decode('UTF-8')
        user.password = hashed_pwd
        db.session.commit()
        flash("Your password has been reset successfully!", "success")
        return redirect('/login')

    return render_template('auth/reset_password.html', form=form)

def send_password_reset_email(user):
    """Send a password reset email."""
    token = generate_reset_token(user)
    reset_url = url_for('reset_password', token=token, _external=True)
    msg = MailMessage(
        "Password Reset Request",
        sender=app.config['MAIL_DEFAULT_SENDER'],
        recipients=[user.email]
    )
    msg.body = f"""To reset your password, visit the following link:
{reset_url}

If you did not make this request, simply ignore this email.
"""
    mail.send(msg)

# Route for reporting abusive behavior

@app.route('/messages/<int:message_id>/report', methods=["POST"])
def report_message(message_id):
    """Report a message for abuse."""
    if not current_user.is_authenticated:
        flash("Access unauthorized.", "danger")
        return redirect('/')

    msg = Message.query.get_or_404(message_id)

    # Save the report to the database
    report = Report(message_id=msg.id, user_id=current_user.id)
    db.session.add(report)
    db.session.commit()

    print("Debug: Flash message triggered")  # Debugging
    flash("Message reported successfully!", "info")
    return redirect(f'/messages/{message_id}')
