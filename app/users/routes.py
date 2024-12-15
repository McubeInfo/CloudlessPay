from flask import request, jsonify
from models import User
from app.schemas import UserSchema
from . import user_bp
from utils.utils import *

@user_bp.get('/all-users')
@token_required
def get_all_users():
    page = request.args.get('page', default=1, type=int)
    per_page = request.args.get('per_page', default=5, type=int)

    pagination = User.query.paginate(page=page, per_page=per_page)
    users = pagination.items
    
    result = UserSchema().dump(users, many=True)
    
    return jsonify({
        "users": result,
        "page": page,
        "total_pages": pagination.pages,
        "total_users": pagination.total
    }), 200
