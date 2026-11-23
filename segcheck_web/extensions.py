"""Shared Flask extensions."""
from pathlib import Path

from flask_login import LoginManager
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect

db = SQLAlchemy()
migrate = Migrate(directory=str(Path(__file__).resolve().parent / "migrations"))
login_manager = LoginManager()
csrf = CSRFProtect()
