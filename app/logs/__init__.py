from flask import Blueprint

logs_bp = Blueprint('logs_bp', __name__)

from . import routes