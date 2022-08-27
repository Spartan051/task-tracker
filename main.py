from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from functools import wraps


app = Flask(__name__)


app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////Users/PC4/Documents/projects/python/database.db'
db = SQLAlchemy(app)

app.config['SECRET_KEY'] = "a6e7300ac1794c679890eabf285997db"


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(50), nullable=False)
    city = db.Column(db.String(50), nullable=False)


class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    person_id = db.Column(db.Integer, nullable=False)
    name = db.Column(db.String(50), nullable=False)
    description = db.Column(db.String(255), nullable=False)


class Log(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, nullable=False)
    date = db.Column(db.String(50), nullable=False)
    value = db.Column(db.String(255), nullable=False)
    notes = db.Column(db.String(255), nullable=False)


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if "Authorization" in request.headers:
            token = request.headers["Authorization"].split(" ")[1]
        if not token:
            return {
                "message": "Authentication Token is missing!",
                "data": None,
                "error": "Unauthorized"
            }, 401
        try:
            data = jwt.decode(
                token, app.config["SECRET_KEY"], algorithms=["HS256"])
            user = User.query.filter_by(username=data["username"]).first()
        except Exception as e:
            return {
                "message": str(e),
            }, 500
        return f(user, *args, **kwargs)
    return decorated


@app.route("/api/login", methods=["POST"])
def get_user_info():
    data = request.get_json()
    user = User.query.filter_by(username=data["username"]).first()

    if not user:
        return jsonify({"message": "user not fownd !"})

    if not check_password_hash(user.password, data["password"]):
        return jsonify({"message": "your password is wrong !"})

    token = jwt.encode({
        "username": user.username
    },
        app.config["SECRET_KEY"])

    user.token = token
    db.session.commit()

    user_data = {}
    user_data["username"] = user.username
    user_data["email"] = user.email
    user_data["city"] = user.city
    user_data["token"] = token

    return jsonify({"data": user_data})


@app.route("/api/register", methods=["POST"])
def create_user():
    data = request.get_json()
    hashed_password = generate_password_hash(data["password"], method="sha256")
    new_user = User(username=data["username"], password=hashed_password,
                    email=data["email"], city=data["city"])
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "new user created !"})


@app.route("/api/task", methods=["POST"])
@token_required
def create_task(user):
    data = request.get_json()
    new_task = Task(person_id=user.id,
                    name=data["name"], description=data["description"])
    db.session.add(new_task)
    db.session.commit()
    return jsonify({"message": "new task created !"})


@app.route("/api/task/<task_id>", methods=["GET"])
@token_required
def get_one_task(user, task_id):
    task = Task.query.filter_by(
        id=task_id,
        person_id=user.id
    ).first()

    task_data = {}
    task_data["name"] = task.name
    task_data["description"] = task.description

    return jsonify({"data": task_data})


@app.route("/api/task", methods=["GET"])
@token_required
def get_all_tasks(user):
    tasks = Task.query.filter_by(person_id=user.id)
    outpot = []
    for task in tasks:
        task_data = {}
        task_data["id"] = task.id
        task_data["name"] = task.name
        task_data["description"] = task.description
        outpot.append(task_data)

    return jsonify({"data": outpot})


@app.route("/api/log", methods=["POST"])
@token_required
def create_log(user):
    data = request.get_json()
    new_log = Log(task_id=data["task_id"],
                  date=data["date"], value=data["value"], notes=data["notes"])
    db.session.add(new_log)
    db.session.commit()
    return jsonify({"message": "new task created !"})


@app.route("/api/log/<task_id>", methods=["GET"])
@token_required
def get_all_logs(user, task_id):
    logs = Task.query.filter_by(task_id=task_id,)

    outpot = []
    for log in logs:
        log_data = {}
        log_data["date"] = log.name
        log_data["value"] = log.value
        log_data["notes"] = log.notes

        outpot.append(log_data)

    return jsonify({"data": outpot})
