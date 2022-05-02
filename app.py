from os.path import join as pj
from os import environ as osenv
from os import listdir
import pathlib
from markupsafe import re

import requests
from flask import Flask, session, abort, redirect, request, url_for, render_template, flash, send_file
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
import google.auth.transport.requests
from flask_sqlalchemy import SQLAlchemy

app = Flask("app")
app.secret_key = "kujvm2.jkbvjnv785"
welcomeMsg = 'Welcome user'
osenv["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

GOOGLE_CLIENT_ID = "926607677403-u9lpkdithrldlsgdvjk52tm0vg196sh1.apps.googleusercontent.com"
client_secrets_file = pj(pathlib.Path(__file__).parent, "client_secret.json")

flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri="http://127.0.0.1:5000/google/auth/"
)

courses = ['Optical Communication', 'Satellite Communication', 'Real Time Operating System', 'Soft Computing', 'Mobile and Wireless Communication']
tutors = {'Optical Communication':'Dr. Ajay Kumar',
            'Satellite Communication': 'Dr. Prashanth', 'Real Time Operating System' : 'Dr. Basudeba Behara', 'Soft Computing': 'Dr. Rashmi Sinha', 
            'Mobile and Wireless Communication': 'Dr. Nagendra Kumar'}

app.config ['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///sso1.sqlite3'
app.config ['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = "random string"

db = SQLAlchemy(app)
class role(db.Model):
   roleid = db.Column('roleid',db.Integer, primary_key = True)
   role = db.Column(db.String(50))
   
   def __init__(self, role):
    self.role = role

class sso(db.Model):
   id = db.Column('id', db.Integer, primary_key = True)
   firstname = db.Column(db.String(100))
   lastname = db.Column(db.String(100))
   username = db.Column(db.String(250))
   googleid = db.Column(db.String(200))
   email = db.Column(db.String(200))
   userid = db.Column(db.String(200))
   role = db.Column(db.Integer, db.ForeignKey('role.roleid'), default=1)

   def __init__(self, f, l, user, gid, email, userid=None, role=1):
    self.firstname = f
    self.lastname = l
    self.username = user
    self.googleid = gid
    self.email = email
    self.userid = userid
    self.role = role

def login_is_required(function):
    def wrapper(*args, **kwargs):
        if "google_id" not in session:
            return redirect(url_for('login'))  # Authorization required
        else:
            if sso.query.with_entities(sso.role).filter(sso.googleid == session['google_id']).all()[0][0]==2:
                kwargs['user_role'] = 2
            else: 
                kwargs['user_role'] = 1
            if sso.query.filter(sso.googleid == session['google_id']).all()!=[]:
                return function(*args, **kwargs)
            else: return function(*args, **kwargs)
    wrapper.__name__ = function.__name__
    return wrapper

def is_admin(function):
    def wrapper(*args, **kwargs):
        if "google_id" in session:
            if sso.query.with_entities(sso.role).filter(sso.googleid == session['google_id']).all()[0][0]==2:
                return function(*args, **kwargs)
            else: abort(401)
        else: return function(*args, **kwargs)
    wrapper.__name__ = function.__name__
    return wrapper

@app.route("/login")
def login():
    return render_template('login.html')

@app.route("/login/sso/google")
def login_sso():
    authorization_url, state = flow.authorization_url(access_type='offline')
    session["state"] = state
    # print(authorization_url)
    return redirect(authorization_url)

@app.route("/google/auth/")
def callback():
    flow.fetch_token(authorization_response=request.url)

    if not session["state"] == request.args["state"]:
        abort(500)  # State does not match!

    credentials = flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID
    )
    session["google_id"] = id_info["sub"]
    session["name"] = id_info["name"]
    if sso.query.filter(sso.googleid == id_info["sub"]).all()==[]:
        ssoUser = sso(id_info['given_name'], id_info['family_name'], id_info['name'], id_info['sub'], id_info['email'], role=1)
        db.session.add(ssoUser)
        db.session.commit()
        print(f'user added {ssoUser.username}')
    print('Existing user signed in.')
    return redirect("/home")

@app.route("/logout", methods=['POST', 'GET'])
def logout(**kwargs):
    session.clear()
    return render_template('redirect.html',time=2,destination='/login', msg='login page . . .')

@app.route("/")
def index(**kwargs):
    return redirect('/login')



@app.route("/home")
@login_is_required
def home(greetMsg='Hello', **kwargs):
    return render_template('HomePage.html',username=session['name'], role = kwargs['user_role'], courses=courses)


@app.route("/manage", methods=['GET','POST'])
@is_admin
@login_is_required
def manage(**kwargs):
    if request.method=='POST':
        rolesDict = {}
        roles = role.query.all()
        for item in roles:
            rolesDict[item.role]=item.roleid
        print(request.form.to_dict())
        form_data = request.form.to_dict()
        for key in form_data.keys():
            sso.query.filter(sso.id == key.split('_')[1]).update({sso.role: rolesDict[form_data[key]]})
        db.session.commit()
        users = sso.query.with_entities(sso.id, sso.email, sso.role).all()
        for user in users:
            print(user.id, user.email, user.role)
        flash('Changes saved on the server.', 'info')
        return redirect('/manage')
    elif request.method=='GET':
        users = sso.query.with_entities(sso.id, sso.email, sso.role).all()
        usersList = []
        userIdList = []
        userRolesList = []
        rolesDict = {}
        user_count = 0
        rolesDictrev = {}
        roles = role.query.all()
        for item in roles:
            rolesDictrev[item.roleid]=item.role
            rolesDict[item.role]=item.roleid
        for user in users:
            user_count+=1
            usersList.append(user.email)
            userIdList.append(user.id)
            userRolesList.append(rolesDictrev[int(user.role)])
        return render_template('manage.html', welcome_msg=welcomeMsg, user_id=userIdList, user_roles=userRolesList, users=usersList
                            , roles= list(rolesDict.keys()), user_count=user_count)


@app.route('/courses/<course>')
def test(course):
    num = len(listdir(f"static/videos/{course}/"))
    print(str(num) +"-"+ course)
    files = []
    for i in range(1,num+1):
        files.append(f"Day {i}")
    course_name=course
    tutor = tutors[course_name]
    print(url_for('static', filename='images/thumbnails/'+course_name+'.jpg'))
    return render_template("/page.html", course_name=course_name, num=3, videos=files, tutor=tutor)


@app.route('/contact')
def contact():
    return render_template('contact.html')


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")