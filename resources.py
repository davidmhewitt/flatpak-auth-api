from flask_restful import Resource, reqparse
from models import UserModel, Purchase, Application
from flask_jwt_extended import (create_access_token, create_refresh_token, jwt_required, jwt_optional, jwt_refresh_token_required, get_jwt_identity, get_raw_jwt)
from datetime import datetime, timedelta
import jwt

shortRepoTokenLifetime = timedelta(minutes=10)
longRepoTokenLifetime = timedelta(days=3650)
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


class PurchasedTokens(Resource):
    def __init__(self):
        self.token_parser = reqparse.RequestParser()
        self.token_parser.add_argument('ids', required=True, type=str, action='append', default=[])

    @jwt_optional
    def post(self):
        data = self.token_parser.parse_args()
        current_user_id = get_jwt_identity()

        logged_in = current_user_id is not None

        denied = []
        tokens = {}
        for app_id in data['ids']:
            denied.append(app_id)

        if logged_in:
            current_user = UserModel.find_by_id (current_user_id)
            if not current_user:
                return {'message': 'Invalid token'}, 401

            for app_id in denied:
                if Purchase.find_purchase(current_user_id, app_id):
                    denied.remove(app_id)
                    tokens[app_id] = jwt.encode({
                        'sub': 'users/%d' % current_user_id,
                        'prefixes': [app_id],
                        'exp': datetime.utcnow() + longRepoTokenLifetime,
                        'name': 'auth.py',
                    }, repo_secret, algorithm='HS256').decode('utf-8')

        return {
            'denied': denied,
            'tokens': tokens
        }

class BeginPurchase(Resource):
    def __init__(self):
        self.token_parser = reqparse.RequestParser()
        self.token_parser.add_argument('app_id', required=True, type=str)
        self.token_parser.add_argument('key', required=True, type=str)
        self.token_parser.add_argument('token', required=True, type=str)
        self.token_parser.add_argument('email', required=True, type=str)
        self.token_parser.add_argument('amount', required=True, type=int)
        self.token_parser.add_argument('currency', required=True, type=str)

    @jwt_optional
    def post(self):
        data = self.token_parser.parse_args()
        app.logger.info(data)
        current_user_id = get_jwt_identity()

        logged_in = current_user_id is not None
        app_id = data['app_id']
        amount = data['amount']
        lifetime = shortRepoTokenLifetime

        # TODO: Actually attempt stripe purchase if amount > 0

        if amount > 0: # And purchase succeeds
            lifetime = longRepoTokenLifetime

        if logged_in:
            new_purchase = Purchase(
                app_id = app_id,
                user_id = current_user_id
            )
            try:
                new_purchase.save_to_db()
            except:
                pass

        token = jwt.encode({
                        'sub': 'users/%d' % (current_user_id if current_user_id else 0),
                        'prefixes': [app_id],
                        'exp': datetime.utcnow() + lifetime,
                        'name': 'auth.py',
                        }, repo_secret, algorithm='HS256').decode('utf-8')

        return_data = { "token": token }
        if amount > 0:
            return_data["store"] = True
        else :
            return_data["store"] = False

        return return_data

class GetApplication(Resource):
    def __init__(self):
        self.id_parser = reqparse.RequestParser()
        self.id_parser.add_argument('id', required=True, type=str)

    def post(self):
        data = self.id_parser.parse_args()

        app = Application.find_by_id(data['id'])
        if not app:
            return {}, 404
        else:
            return {
                "id": app.app_id,
                "name": app.name,
                "stripe_key": app.stripe_key,
                "recommended_amount": app.recommended_amount
            }
