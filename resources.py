from flask_restful import Resource, reqparse
from models import UserModel, Purchase
from flask_jwt_extended import (create_access_token, create_refresh_token, jwt_required, jwt_refresh_token_required, get_jwt_identity, get_raw_jwt)
from datetime import datetime, timedelta
import jwt

repoTokenLifetime = timedelta(minutes=10)
repo_secret="SECRET PURCHASE TOKEN"

credential_parser = reqparse.RequestParser()
credential_parser.add_argument('username', help = 'This field cannot be blank', required = True)
credential_parser.add_argument('password', help = 'This field cannot be blank', required = True)

class UserRegistration(Resource):
    def post(self):
        data = credential_parser.parse_args()

        if UserModel.find_by_username(data['username']):
          return {'message': 'User {} already exists'. format(data['username'])}

        new_user = UserModel(
            username = data['username'],
            password = UserModel.generate_hash(data['password'])
        )
        try:
            new_user.save_to_db()
            return {
                'message': 'User {} was created'.format(data['username'])
            }
        except:
            return {'message': 'Something went wrong'}, 500


class UserLogin(Resource):
    def post(self):
        data = credential_parser.parse_args()
        current_user = UserModel.find_by_username(data['username'])
        if not current_user:
            return {'message': 'User {} doesn\'t exist'.format(data['username'])}, 401

        if UserModel.verify_hash(data['password'], current_user.password):
            access_token = create_access_token(identity = current_user.id, expires_delta=timedelta(days=30))
            return {
                'message': 'Logged in as {}'.format(current_user.username),
                'access_token': access_token,
            }
        else:
            return {'message': 'Wrong credentials'}, 401

class TokenRefresh(Resource):
    def post(self):
        return {'message': 'Token refresh'}


class GetPurchasedTokens(Resource):
    def __init__ (self):
        self.token_parser = reqparse.RequestParser()
        self.token_parser.add_argument('ids', required=False, type=str, action='append', default=[])

    @jwt_required
    def post(self):
        data = self.token_parser.parse_args ()
        current_user_id = get_jwt_identity()

        current_user = UserModel.find_by_id (current_user_id)
        if not current_user:
            return {'message': 'Invalid token'}, 401

        denied = []
        tokens = {}
        for app_id in data['ids']:
            denied.append(app_id)

        for app_id in denied:
            if Purchase.find_purchase(current_user_id, app_id):
                denied.remove(app_id)
                tokens[app_id] = jwt.encode({
                    'sub': 'users/%d' % current_user_id,
                    'prefixes': [app_id],
                    'exp': datetime.utcnow() + repoTokenLifetime,
                    'name': 'auth.py',
                }, repo_secret, algorithm='HS256').decode('utf-8')

        return {
            'denied': denied,
            'tokens': tokens
        }
