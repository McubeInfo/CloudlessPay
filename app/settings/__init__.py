from flask import Blueprint

settings_bp = Blueprint('settings_bp', __name__)

from . import routes