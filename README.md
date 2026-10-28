\# JWKS Server (Project 2)



Flask server that stores RSA private keys in a SQLite database and serves

them as a JWKS. Keys are stored in totally\_not\_my\_privateKeys.db using

parameterized queries.



\## Setup



&#x20;   python -m venv venv

&#x20;   .\\venv\\Scripts\\Activate.ps1

&#x20;   pip install -r requirements.txt



\## Run



&#x20;   python app.py



The server listens on http://localhost:8080.



\## Endpoints



\- GET /.well-known/jwks.json returns all unexpired public keys.

\- POST /auth returns a signed JWT. Add ?expired=true to get a JWT signed

&#x20; with an expired key.



\## Test and lint



&#x20;   pytest --cov=app --cov-report=term-missing

&#x20;   ruff check .

