"""SQLAlchemy models for Warbler."""

from datetime import datetime

from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

bcrypt = Bcrypt()
db = SQLAlchemy()


class Follows(db.Model):
    """Connection of a follower <-> followed_user."""

    __tablename__ = 'follows'

    user_being_followed_id = db.Column(
        db.Integer,
        db.ForeignKey('users.id', ondelete="cascade"),
        primary_key=True,
    )

    user_following_id = db.Column(
        db.Integer,
        db.ForeignKey('users.id', ondelete="cascade"),
        primary_key=True,
    )


class Likes(db.Model):
    """Mapping user likes to warbles."""

    __tablename__ = 'likes' 

    user_id = db.Column(
        db.Integer,
        db.ForeignKey('users.id', ondelete='cascade'),
        primary_key=True
    )

    message_id = db.Column(
        db.Integer,
        db.ForeignKey('messages.id', ondelete='cascade'),
        primary_key=True
        
    )


class User(UserMixin, db.Model):
    """User in the system."""

    __tablename__ = 'users'

    id = db.Column(
        db.Integer,
        primary_key=True,
    )

    email = db.Column(
        db.String(120),
        nullable=False,
        unique=True,
    )

    is_confirmed = db.Column(
        db.Boolean,
        default=False
    )

    username = db.Column(
        db.Text,
        nullable=False,
        unique=True,
    )

    image_url = db.Column(
        db.Text,
        default="/static/images/default-pic.png",
    )

    header_image_url = db.Column(
        db.Text,
        default="/static/images/squawk-hero.png"
    )

    bio = db.Column(
        db.Text,
    )

    location = db.Column(
        db.Text,
    )

    password = db.Column(
        db.Text,
        nullable=False,
    )

    is_admin = db.Column(db.Boolean, default=False)  # New field for admin privileges

    # New fields for social media links
    twitter_url = db.Column(
        db.String(200),
        nullable=True,
    )

    facebook_url = db.Column(
        db.String(200),
        nullable=True,
    )

    linkedin_url = db.Column(
        db.String(200),
        nullable=True,
    )

    # Relationship for messages authored by the user
    messages = db.relationship('Message', backref='user_messages', cascade="all, delete-orphan", overlaps="author")

    followers = db.relationship(
        "User",
        secondary="follows",
        primaryjoin=(Follows.user_being_followed_id == id),
        secondaryjoin=(Follows.user_following_id == id),
        overlaps="following"
    )

    following = db.relationship(
        "User",
        secondary="follows",
        primaryjoin=(Follows.user_following_id == id),
        secondaryjoin=(Follows.user_being_followed_id == id),
        overlaps="followers"
    )

    # Relationship for messages liked by the user
    likes = db.relationship(
        'Message',
        secondary="likes",
        backref="liked_by_users",
        overlaps="liked_by"
    )

    def __repr__(self):
        return f"<User #{self.id}: {self.username}, {self.email}>"

    def is_followed_by(self, other_user):
        """Is this user followed by `other_user`?"""

        found_user_list = [user for user in self.followers if user == other_user]
        return len(found_user_list) == 1

    def is_following(self, other_user):
        """Is this user following `other_use`?"""

        found_user_list = [user for user in self.following if user == other_user]
        return len(found_user_list) == 1
    
    def has_liked_message(self, message):
         """Check if the user has liked a specific message."""
         return message in self.likes

    def toggle_like(self, message):
        """Toggle like/unlike for a specific message."""
        if message.user_id == self.id:
            raise ValueError("Users cannot like their own messages.")
        if message in self.likes:
            self.likes.remove(message)
        else:
            self.likes.append(message)
    
    def check_confirmation(self):
        """Check if the user is confirmed."""
        return self.is_confirmed

    @classmethod
    def signup(cls, username, email, password, image_url):
        """Sign up user.

        Hashes password and adds user to system.
        """

        hashed_pwd = bcrypt.generate_password_hash(password).decode('UTF-8')

        user = User(
            username=username,
            email=email,
            password=hashed_pwd,
            image_url=image_url,
        )

        db.session.add(user)
        return user

    @classmethod
    def authenticate(cls, username, password):
        """Find user with `username` and `password`.

        This is a class method (call it on the class, not an individual user.)
        It searches for a user whose password hash matches this password
        and, if it finds such a user, returns that user object.

        If can't find matching user (or if password is wrong), returns False.
        """

        user = cls.query.filter_by(username=username).first()

        if user:
            is_auth = bcrypt.check_password_hash(user.password, password)
            if is_auth:
                return user

        return False


class Message(db.Model):
    """An individual message ("squauk")."""

    __tablename__ = 'messages'

    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(140), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)

    # New field for replies
    parent_id = db.Column(db.Integer, db.ForeignKey('messages.id', ondelete='CASCADE'), nullable=True)

    # Relationships
    author = db.relationship('User', overlaps="messages, user_messages")
    liked_by = db.relationship('User', secondary="likes", overlaps="liked_by_users")
    replies = db.relationship('Message', backref=db.backref('parent', remote_side=[id]), cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Message #{self.id}: {self.text[:20]}...>"

class Report(db.Model):
    """A report for abusive messages."""

    __tablename__ = 'reports'

    id = db.Column(db.Integer, primary_key=True)
    message_id = db.Column(db.Integer, db.ForeignKey('messages.id', ondelete='CASCADE'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    message = db.relationship('Message', backref='reports')
    user = db.relationship('User', backref='reports')

def connect_db(app):
    """Connect this database to provided Flask app.

    You should call this in your Flask app.
    """

    db.app = app
    db.init_app(app)
