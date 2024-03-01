# add_user.py

from app import create_app, db  # Import your Flask application and database instance
from app.models import User  # Import the User model from your models (adjust the path as needed)
from flask_bcrypt import Bcrypt

# Initialize Flask application context
app = create_app()
bcrypt = Bcrypt(app)

def add_user(username, password):
    with app.app_context():
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')  # Hash the password
        new_user = User(username=username, password=hashed_password)  # Create a new User instance
        db.session.add(new_user)  # Add new User to the database session
        db.session.commit()  # Commit the session to save changes
        print(f"User {username} added successfully.")

if __name__ == '__main__':
    add_user('admin', '!!Bird123')  # Change 'admin' and '!!Bird123' if you want to add different users
