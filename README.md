In-Need App Backend

Backend for the In-Need Sponsorship App, built with Flask and PostgreSQL.

Setup


Navigate to backend/:

cd backend


Create and activate a virtual environment:

python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate


Install dependencies:

pip install -r requirements.txt

Set up PostgreSQL:


Create a database named inneed_db.


Update instance/.env with your database credentials.


Initialize the database:

flask db init
flask db migrate
flask db upgrade

Run the app:

python run.py

Notes

Ensure PostgreSQL is running locally or update DATABASE_URL for a remote instance.



The app serves templates from frontend/templates and static files from frontend/static.