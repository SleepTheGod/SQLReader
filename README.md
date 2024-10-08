# SQL Reader To Read Large SQL Files In A FLASK APPLICATION

How to install and run properly
```bash
git clone https://github.com/SleepTheGod/SQLReader/
cd SQLReader
chmod +x app.py
pip install -r requirements.txt
pip install Flask==2.3.3
pip install Werkzeug==2.3.3
pip install cryptography==39.0.1
python app.py
```
# Now visit the following
127.0.1:5000 to visit your new application.
If done correctly all should be working.

Structure of files
```
SQLReader/
│
├── app.py                # Main Flask application
├── templates/
│   └── index.html         # Upload form and results display
└── uploads/               # Directory to store uploaded files temporarily
```
