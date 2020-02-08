from run import db
from passlib.hash import pbkdf2_sha256 as sha256

class UserModel(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(120), unique = True, nullable = False)
    password = db.Column(db.String(120), nullable = False)

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

    @staticmethod
    def generate_hash(password):
        return sha256.hash(password)
    @staticmethod
    def verify_hash(password, hash):
        return sha256.verify(password, hash)

    @classmethod
    def find_by_username(cls, username):
        return cls.query.filter_by(username = username).first()

    @classmethod
    def find_by_id(cls, id):
        return cls.query.filter_by(id = id).first()

class Purchase(db.Model):
    __tablename__ = 'purchases'
    app_id = db.Column(db.String, primary_key = True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    until = db.Column(db.DateTime(timezone=True))

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

    @classmethod
    def find_purchase(cls, user, app_id):
        return cls.query.filter_by(user_id = user, app_id = app_id).first()

class Application(db.Model):
    __tablename__ = "applications"
    app_id = db.Column(db.String, primary_key = True, unique = True)
    name = db.Column(db.String)
    stripe_key = db.Column(db.String)
    recommended_amount = db.Column(db.Integer)

    @classmethod
    def find_by_id(cls, id):
        return cls.query.filter_by(app_id = id).first()
