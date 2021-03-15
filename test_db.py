import os
import pytest
import tempfile
import app as app

# import db classes
from app import User

# import IntegrityError
from sqlalchemy.exc import IntegrityError


# from course material

@pytest.fixture
def db_handle():
    db_fd, db_fname = tempfile.mkstemp()
    app.app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + db_fname
    app.app.config["TESTING"] = True

    with app.app.app_context():
        app.db.create_all()

    yield app.db

    app.db.session.remove()
    os.close(db_fd)
    os.unlink(db_fname)


def test_user(db_handle):
    """
    class User(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        username = db.Column(db.String(256), nullable=False)
        email = db.Column(db.String(256), nullable=False)
        pw_hash = db.Column(db.String(256), nullable=False)
        conversations = db.relationship("Conv", back_populates="user")
    """

    ### Test creating
    user = User(username='username',
                email='test@email.com',
                pw_hash='12345')
    db_handle.session.add(user)
    db_handle.session.commit()
    assert User.query.count() == 1

    ### Check the username
    user = User.query.filter_by(username='username').first()
    assert user.username == 'username'

    ### Test that having no username gives an error
    user = User(email='test@email.com',
                pw_hash='12345')
    db_handle.session.add(user)

    # committing now should raise an error
    with pytest.raises(IntegrityError):
        db_handle.session.commit()

    # rollback after error
    db_handle.session.rollback()

    ### Test unique username
    user = User(username='username',
                email='test@email.com',
                pw_hash='12345')
    db_handle.session.add(user)

    # committing now should raise an IntegrityError: UNIQUE constraint failed
    with pytest.raises(IntegrityError):
        db_handle.session.commit()

    # rollback after error
    db_handle.session.rollback()

    ### Test deleting
    # add one more
    user = User(username='username2',
                email='test@email.com',
                pw_hash='12345')
    db_handle.session.add(user)
    db_handle.session.commit()

    # Count should be 2 now
    assert user.query.count() == 2

    # delete
    user = User.query.filter_by(username='username').first()
    db_handle.session.delete(user)
    db_handle.session.commit()

    # deleted?
    assert user.query.count() == 1