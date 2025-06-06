import os
from unittest import TestCase
from models import db, User, Message

# Set up a test database
os.environ['DATABASE_URL'] = "postgresql:///warbler-test"

from app import app

class MessageModelTestCase(TestCase):
    """Test the Message model and likes functionality."""

    def setUp(self):
        """Set up test data."""
        # Set up the application context
        self.app = app
        self.app_context = self.app.app_context()
        self.app_context.push()

        # Reset the database
        db.drop_all()
        db.create_all()

        # Create two users
        self.user1 = User.signup("user1", "user1@test.com", "password", None)
        self.user2 = User.signup("user2", "user2@test.com", "password", None)
        db.session.commit()

        # Create two messages
        self.msg1 = Message(text="Message 1", user_id=self.user1.id)
        self.msg2 = Message(text="Message 2", user_id=self.user2.id)
        db.session.add_all([self.msg1, self.msg2])
        db.session.commit()

        self.client = app.test_client()

    def tearDown(self):
        """Clean up fouled transactions."""
        db.session.rollback()
        db.drop_all()

        # Pop the application context
        self.app_context.pop()

    def test_user_can_like_message(self):
        """Test that a user can like a message."""
        self.user1.likes.append(self.msg2)
        db.session.commit()

        # Check that the like was added
        self.assertIn(self.msg2, self.user1.likes)
        self.assertEqual(len(self.user1.likes), 1)

    def test_user_cannot_like_own_message(self):
        """Test that a user cannot like their own message."""
        with self.assertRaises(ValueError):
            self.user1.toggle_like(self.msg1)
            db.session.commit()

    def test_user_can_unlike_message(self):
        """Test that a user can unlike a message."""
        self.user1.likes.append(self.msg2)
        db.session.commit()

        # Unlike the message
        self.user1.likes.remove(self.msg2)
        db.session.commit()

        # Check that the like was removed
        self.assertNotIn(self.msg2, self.user1.likes)
        self.assertEqual(len(self.user1.likes), 0)

    def test_likes_relationship(self):
        """Test the likes relationship between User and Message."""
        self.user1.likes.append(self.msg2)
        db.session.commit()

        # Check that the message is liked by the user
        self.assertIn(self.user1, self.msg2.liked_by)
        self.assertEqual(len(self.msg2.liked_by), 1)

    def test_multiple_users_can_like_same_message(self):
        """Test that multiple users can like the same message."""
        self.user1.likes.append(self.msg2)
        self.user2.likes.append(self.msg2)
        db.session.commit()

        # Check that both users liked the same message
        self.assertIn(self.user1, self.msg2.liked_by)
        self.assertIn(self.user2, self.msg2.liked_by)
        self.assertEqual(len(self.msg2.liked_by), 2)