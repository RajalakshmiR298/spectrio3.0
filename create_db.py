from app import app, db

# Push the application context and create tables
with app.app_context():
    db.create_all()  # This will create the tables in the database
