from flask import Flask
from flask_sqlalchemy import SQLAlchemy

app = Flask (__name__)
app.config ['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///sso1.sqlite3'
app.config ['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = "egr561svdxc56"

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
# db.create_all()
# db.session.commit()

# def add_column(engine, table_name, column):
#     column_name = column.compile(dialect=engine.dialect)
#     column_type = column.type.compile(engine.dialect)
#     engine.execute('ALTER TABLE %s ADD COLUMN %s %s' % (table_name, column_name, column_type))

# column = db.Column('new_column_name', db.String(100), primary_key=True)
# add_column(db.engine, db.sso, column)

users = sso.query.all()
for user in users:
    print(user.username, user.role)

# userrole = role('User')
# adminrole = role('Admin')

# db.session.add(userrole)
# db.session.add(adminrole)
# db.session.commit()

roles = role.query.all()
for role in roles:
    print(role.roleid, role.role)

# print(sso.query.with_entities(sso.role).filter(sso.googleid == '101921290062744986130').all()[0][0])
# user = sso.query.filter(sso.googleid == '101921290062744986130').all()[0]
users = sso.query.with_entities(sso.id, sso.email, sso.role).all()
sso.query.filter(sso.id == 2).update({sso.role : 1})
db.session.commit()
print(users)
for user in users:
    print(user.id, user.email, user.role)
db.session.commit()

sso.add()