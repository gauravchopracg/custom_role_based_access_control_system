from flask import Flask, render_template, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from datetime import datetime
from flask_migrate import Migrate

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
migrate = Migrate(app, db)

role_permission = db.Table('role_permission',
                    db.Column('role_id', db.Integer, db.ForeignKey('role.id')),
                    db.Column('permission_id', db.Integer, db.ForeignKey('permission.id'))
                    )

user_role = db.Table('user_role',
                    db.Column('user_id', db.Integer, db.ForeignKey('user.id')),
                    db.Column('role_id', db.Integer, db.ForeignKey('role.id'))
                    )

class User(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(120), unique=True, nullable=False)
	email = db.Column(db.String(120), unique=True, nullable=False)
	# password = db.Column(db.String(120), nullable=False)

	def __repr__(self):
		return '<User {}>'.format(self.username)

class Permission(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	description = db.Column(db.String(120), nullable=False)
	name = db.Column(db.String(120), nullable=False)
	# action = db.Column(db.String(120), nullable=False)
	# resource = db.Column(db.String(120), nullable=False)

	def __repr__(self):
		return '<Permission {}>'.format(self.description)

class Role(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	name = db.Column(db.String(120), nullable=False)
	hashed_api_key = db.Column(db.String(120), nullable=False)
	permissions = db.relationship('Permission', secondary=role_permission, backref='roles')
	users = db.relationship('User', secondary=user_role, backref='roles')

	def __repr__(self):
		return '<Role {}>'.format(self.name)

class Attempt(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	access = db.Column(db.String(120), nullable=False)
	# access : granted / denied
	api = db.Column(db.String(120), nullable=False)
	request = db.Column(db.String(120), nullable=False)
	attempt_time = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
	attempt_message = db.Column(db.String(120), nullable=False)

	# add attempt - access / denied

	def __repr__(self):
		return '<Attempt {}>'.format(self.attempt_time)

# Create users.
@app.route('/users/register')
def register():
	# declare variable to be used in the function
	request_data = request.json
	# print(request_data)
	# print(request_data.keys())
	attempt_data = {}
	return_data = {}

	# Log each access attempt with outcomes (granted or denied).
	api = request.base_url
	attempt_data['api'] = str(api)
	attempt_data['request'] = str(request_data)
	attempt_data['access'] = 'Denied'
	attempt_data['message'] = "Access Denied. Please check the format of the request."

	# print(api)
	# request = request_data

	# Access Validation: a) Design APIs to validate whether a user can perform a specific action on a resource based on their assigned roles and permissions.
	if 'api_key' not in list(request_data.keys()) or 'data' not in list(request_data.keys()):
		return_data['message'] = "Access Denied. Please check the format of the request."
		attempt_data['message'] = "Access Denied. Please check the format of the request."
		return_data['success'] = False
		attempt_data['access'] = 'Denied'

		attempt = Attempt(access=attempt_data['access'], api=attempt_data['api'], request=attempt_data['request'], attempt_message=attempt_data['message'])
		db.session.add(attempt)
		db.session.commit()
		return jsonify(return_data)

	api_key = request_data["api_key"]
	data = request_data['data']

	role_name = ''

	# list of api key present
	roles = Role.query.all()

	for role in roles:

		if bcrypt.check_password_hash(role.hashed_api_key, api_key):
			role_name = role.name
			permissions = role.permissions
			permissions = [permission.name for permission in permissions]

	if role_name:
		return_data['message'] = "Access Denied. You don't have enough permission to create user. Please contact adminstrator to assign permission."
		attempt_data['message'] = "Access Denied. You don't have enough permission to create user. Please contact adminstrator to assign permission."
		return_data['success'] = False
		attempt_data['access'] = 'Denied'

		# check permissions of role
		if 'create_users' in permissions:
			return_data['message'] = "Access Granted. Created user. Please contact adminstrator to assign role to this user."
			attempt_data['message'] = "Access Granted. Created user. Please contact adminstrator to assign role to this user."
			return_data['success'] = True
			attempt_data['access'] = 'Granted'

			create_username = data['username']
			create_email = data['email']
			# create_password = data['password']
			# create_user_role = data['role']

			# hash password and add it in database
			# hashed_password = bcrypt.generate_password_hash(create_password).decode('utf-8')

			# add role id while creating user
			# role_1 = Role.query.first()

			create_user = User(username=create_username, email=create_email) # , role_id=role_1.id)
			db.session.add(create_user)
			db.session.commit()

			return_data['data'] = data

			attempt = Attempt(access=attempt_data['access'], api=attempt_data['api'], request=attempt_data['request'], attempt_message=attempt_data['message'])
			db.session.add(attempt)
			db.session.commit()
			return jsonify(return_data)

		else:
			attempt = Attempt(access=attempt_data['access'], api=attempt_data['api'], request=attempt_data['request'], attempt_message=attempt_data['message'])
			db.session.add(attempt)
			db.session.commit()
			return jsonify(return_data)

	else:
		return_data['message'] = "Access Denied. Please contact adminstrator to get correct api key."
		attempt_data['message'] = "Access Denied. Please contact adminstrator to get correct api key."
		return_data['success'] = False
		attempt_data['access'] = 'Denied'
		# return_data['data'] = request_data

		attempt = Attempt(access=attempt_data['access'], api=attempt_data['api'], request=attempt_data['request'], attempt_message=attempt_data['message'])
		db.session.add(attempt)
		db.session.commit()
		return jsonify(return_data)

# Retrieve user lists.
@app.route("/users")
def users():
	# declare variable to be used in the function
	request_data = request.json
	# print(request_data)
	# print(request_data.keys())
	attempt_data = {}
	return_data = {}

	# Log each access attempt with outcomes (granted or denied).
	api = request.base_url
	attempt_data['api'] = str(api)
	attempt_data['request'] = str(request_data)
	attempt_data['access'] = 'Denied'
	attempt_data['message'] = "Access Denied. Please check the format of the request."

	# print(api)
	# request = request_data

	# Access Validation: a) Design APIs to validate whether a user can perform a specific action on a resource based on their assigned roles and permissions.
	if 'api_key' not in list(request_data.keys()):
		return_data['message'] = "Access Denied. Please check the format of the request."
		attempt_data['message'] = "Access Denied. Please check the format of the request."
		return_data['success'] = False
		attempt_data['access'] = 'Denied'

		attempt = Attempt(access=attempt_data['access'], api=attempt_data['api'], request=attempt_data['request'], attempt_message=attempt_data['message'])
		db.session.add(attempt)
		db.session.commit()
		return jsonify(return_data)

	api_key = request_data["api_key"]
	# data = request_data['data']

	role_name = ''

	# list of api key present
	roles = Role.query.all()

	for role in roles:

		if bcrypt.check_password_hash(role.hashed_api_key, api_key):
			role_name = role.name
			permissions = role.permissions
			permissions = [permission.name for permission in permissions]

	if role_name:
		return_data['message'] = "Access Denied. You don't have enough permission to create user. Please contact adminstrator to assign permission."
		attempt_data['message'] = "Access Denied. You don't have enough permission to create user. Please contact adminstrator to assign permission."
		return_data['success'] = False
		attempt_data['access'] = 'Denied'

		# check permissions of role
		if 'retrieve_user_list' in permissions:
			return_data['message'] = "Access Granted. List of users with id, username, email, and role."
			attempt_data['message'] = "Access Granted. List of users with id, username, email, and role."
			return_data['success'] = True
			attempt_data['access'] = 'Granted'

			user_list = User.query.all()
			retrieve_user_list = []

			for user in user_list:
				user_data = {}
				user_data['user_id'] = user.id
				user_data['username'] = user.username
				user_data['email'] = user.email
				user_data['role'] = user.roles
				user_data['role'] = ', '.join([role.name for role in user_data['role']])

				retrieve_user_list.append(user_data)

			return_data['data'] = retrieve_user_list

			attempt = Attempt(access=attempt_data['access'], api=attempt_data['api'], request=attempt_data['request'], attempt_message=attempt_data['message'])
			db.session.add(attempt)
			db.session.commit()
			return jsonify(return_data)

		else:
			attempt = Attempt(access=attempt_data['access'], api=attempt_data['api'], request=attempt_data['request'], attempt_message=attempt_data['message'])
			db.session.add(attempt)
			db.session.commit()
			return jsonify(return_data)

	else:
		return_data['message'] = "Access Denied. Please contact adminstrator to get correct api key."
		attempt_data['message'] = "Access Denied. Please contact adminstrator to get correct api key."
		return_data['success'] = False
		attempt_data['access'] = 'Denied'
		# return_data['data'] = request_data

		attempt = Attempt(access=attempt_data['access'], api=attempt_data['api'], request=attempt_data['request'], attempt_message=attempt_data['message'])
		db.session.add(attempt)
		db.session.commit()
		return jsonify(return_data)

# Assign predefined roles (staff, supervisor, admin) to users.
@app.route('/users/assign_role/<int:user_id>')
def assign_role(user_id):
	# declare variable to be used in the function
	request_data = request.json
	# print(request_data)
	# print(request_data.keys())
	attempt_data = {}
	return_data = {}

	# Log each access attempt with outcomes (granted or denied).
	api = request.base_url
	attempt_data['api'] = str(api)
	attempt_data['request'] = str(request_data)
	attempt_data['access'] = 'Denied'
	attempt_data['message'] = "Access Denied. Please check the format of the request."

	# print(api)
	# request = request_data

	# Access Validation: a) Design APIs to validate whether a user can perform a specific action on a resource based on their assigned roles and permissions.
	if 'api_key' not in list(request_data.keys()) or 'data' not in list(request_data.keys()):
		return_data['message'] = "Access Denied. Please check the format of the request."
		attempt_data['message'] = "Access Denied. Please check the format of the request."
		return_data['success'] = False
		attempt_data['access'] = 'Denied'

		attempt = Attempt(access=attempt_data['access'], api=attempt_data['api'], request=attempt_data['request'], attempt_message=attempt_data['message'])
		db.session.add(attempt)
		db.session.commit()
		return jsonify(return_data)

	api_key = request_data["api_key"]
	data = request_data['data']

	role_name = ''

	# list of api key present
	roles = Role.query.all()

	for role in roles:

		if bcrypt.check_password_hash(role.hashed_api_key, api_key):
			role_name = role.name
			permissions = role.permissions
			permissions = [permission.name for permission in permissions]

	if role_name:
		return_data['message'] = "Access Denied. You don't have enough permission to create user. Please contact adminstrator to assign permission."
		attempt_data['message'] = "Access Denied. You don't have enough permission to create user. Please contact adminstrator to assign permission."
		return_data['success'] = False
		attempt_data['access'] = 'Denied'

		# check permissions of role
		if 'assign_user_role' in permissions:

			return_data['message'] = "Access Granted. Assigned role to the user."
			attempt_data['message'] = "Access Granted. Assigned role to the user."
			return_data['success'] = True
			attempt_data['access'] = 'Granted'

			# fetch username or user id
			user_username = data['username']

			# fetch role name or role id
			assign_role_user = data['role']

			# fetch user
			user = User.query.filter_by(username=user_username).first()

			# fetch role
			role = Role.query.filter_by(name=assign_role_user).first()

			# check if user has pre-defined role and remove all the roles and only assign 1 role
			# predefined_role = user.roles
			# predefined_role = [_.name for _ in predefined_role]

			# if role_1 in permission_1.roles:
				# permission_1.roles.remove(role_1)
				# return_data['message'] = "Access Granted. Revoked Permission from this role."

			# assign role to user
			user.roles = [role]

			# save changes
			db.session.commit()

			return_data['data'] = data
			return jsonify(return_data)

		else:
			return jsonify(return_data)

	else:
		return_data['message'] = "Access Denied. Please contact adminstrator to get correct api key."
		return_data['success'] = False
		attempt_data['access'] = 'Denied'
		# return_data['data'] = request_data
		return jsonify(return_data)

# Retrieve the list of roles.
@app.route('/roles')
def roles():
	# declare variable to be used in the function
	request_data = request.json
	attempt_data = {}
	return_data = {}

	# request_data = request_data['data']

	# print(request_data)

	# Log each access attempt with outcomes (granted or denied).
	# api = request.base_url
	# print(api)
	# request = request_data

	# attempt = Attempt(api=api, request=str(request_data))

	# db.session.add(attempt)
	# db.session.commit()

	# Access Validation: a) Design APIs to validate whether a user can perform a specific action on a resource based on their assigned roles and permissions.
	api_key = request_data["api_key"]
	page_number = request_data["page"]

	role_name = ''

	# list of api key present
	roles = Role.query.all()

	for role in roles:

		if bcrypt.check_password_hash(role.hashed_api_key, api_key):
			role_name = role.name
			permissions = role.permissions
			permissions = [permission.name for permission in permissions]

	if role_name:
		return_data['message'] = "Access Denied. Please contact adminstrator to assign permission to this role."
		return_data['success'] = False
		attempt_data['access'] = 'Denied'

		# check permissions of role
		if 'retrieve_roles' in permissions:
			return_data['message'] = "Access Granted. List of roles with username, email, and role."
			return_data['success'] = True
			attempt_data['access'] = 'Granted'

			role_list = Role.query.all()
			retrieve_role_list = []

			for role in role_list:
				retrieve_role_list += [role.name]

			# retrieve_role_list = ', '.join(retrieve_role_list)
			return_data['data'] = retrieve_role_list
			return jsonify(return_data)

		else:
			return jsonify(return_data)

	else:
		return_data['message'] = "Access Denied. Please contact adminstrator to get correct api key."
		return_data['success'] = False
		attempt_data['access'] = 'Denied'
		# return_data['data'] = request_data
		return jsonify(return_data)

# Dynamically assign permissions to these roles. Only Admin should have the ability to assign permissions.
@app.route('/roles/assign_permission/<int:role_id>')
def assign_permission(role_id):
	# declare variable to be used in the function
	request_data = request.json
	# print(request_data)
	# print(request_data.keys())
	attempt_data = {}
	return_data = {}

	# Log each access attempt with outcomes (granted or denied).
	api = request.base_url
	attempt_data['api'] = str(api)
	attempt_data['request'] = str(request_data)
	attempt_data['access'] = 'Denied'
	attempt_data['message'] = "Access Denied. Please check the format of the request."

	# print(api)
	# request = request_data

	# Access Validation: a) Design APIs to validate whether a user can perform a specific action on a resource based on their assigned roles and permissions.
	if 'api_key' not in list(request_data.keys()) or 'data' not in list(request_data.keys()):
		return_data['message'] = "Access Denied. Please check the format of the request."
		attempt_data['message'] = "Access Denied. Please check the format of the request."
		return_data['success'] = False
		attempt_data['access'] = 'Denied'

		attempt = Attempt(access=attempt_data['access'], api=attempt_data['api'], request=attempt_data['request'], attempt_message=attempt_data['message'])
		db.session.add(attempt)
		db.session.commit()
		return jsonify(return_data)

	api_key = request_data["api_key"]
	data = request_data['data']

	role_name = ''

	# list of api key present
	roles = Role.query.all()

	for role in roles:

		if bcrypt.check_password_hash(role.hashed_api_key, api_key):
			role_name = role.name
			permissions = role.permissions
			permissions = [permission.name for permission in permissions]

	if role_name:
		return_data['message'] = "Access Denied. You don't have enough permission to create user. Please contact adminstrator to assign permission."
		attempt_data['message'] = "Access Denied. You don't have enough permission to create user. Please contact adminstrator to assign permission."
		return_data['success'] = False
		attempt_data['access'] = 'Denied'

		# check permissions of role
		if 'assign_permission' in permissions:
			return_data['message'] = "Access Granted. Assigned role to the user."
			attempt_data['message'] = "Access Granted. Assigned role to the user."
			return_data['success'] = True
			attempt_data['access'] = 'Granted'

			# permission to assign
			permission_1 = Permission.query.filter_by(name=data['permission']).first()
			# print(permission_1)

			# role to assign
			role_1 = Role.query.filter_by(name=data['role']).first()
			# print(role_1)

			# print(data['action'])

			if data['action'] == 'allow':
				# print('allow-data')
				
				# assign
				permission_1.roles += [role_1]
				return_data['message'] = "Access Granted. Assigned Permission to this role."
				attempt_data['message'] = "Access Granted. Assigned Permission to this role."

			else:

				if role_1 in permission_1.roles:
					permission_1.roles.remove(role_1)
					return_data['message'] = "Access Granted. Revoked Permission from this role."
					attempt_data['message'] = "Access Granted. Revoked Permission from this role."
				else:
					return_data['message'] = "Access Granted. Permission hasn't been assigned to role. To Revoke Permission, Please assign it first."
					attempt_data['message'] = "Access Granted. Permission hasn't been assigned to role. To Revoke Permission, Please assign it first."

			# save changes
			db.session.commit()
			return_data['data'] = data

			attempt = Attempt(access=attempt_data['access'], api=attempt_data['api'], request=attempt_data['request'], attempt_message=attempt_data['message'])
			db.session.add(attempt)
			db.session.commit()
			return jsonify(return_data)

		else:
			attempt = Attempt(access=attempt_data['access'], api=attempt_data['api'], request=attempt_data['request'], attempt_message=attempt_data['message'])
			db.session.add(attempt)
			db.session.commit()
			return jsonify(return_data)

	else:
		return_data['message'] = "Access Denied. Please contact adminstrator to get correct api key."
		attempt_data['message'] = "Access Denied. Please contact adminstrator to get correct api key."
		return_data['success'] = False
		attempt_data['access'] = 'Denied'
		# return_data['data'] = request_data

		attempt = Attempt(access=attempt_data['access'], api=attempt_data['api'], request=attempt_data['request'], attempt_message=attempt_data['message'])
		db.session.add(attempt)
		db.session.commit()
		return jsonify(return_data)

# List all available permissions.
@app.route('/permissions')
def permissions():
	# declare variable to be used in the function
	request_data = request.json
	# print(request_data)
	# print(request_data.keys())
	attempt_data = {}
	return_data = {}

	# Log each access attempt with outcomes (granted or denied).
	api = request.base_url
	attempt_data['api'] = str(api)
	attempt_data['request'] = str(request_data)
	attempt_data['access'] = 'Denied'
	attempt_data['message'] = "Access Denied. Please check the format of the request."

	# print(api)
	# request = request_data

	# Access Validation: a) Design APIs to validate whether a user can perform a specific action on a resource based on their assigned roles and permissions.
	if 'api_key' not in list(request_data.keys()):
		return_data['message'] = "Access Denied. Please check the format of the request."
		attempt_data['message'] = "Access Denied. Please check the format of the request."
		return_data['success'] = False
		attempt_data['access'] = 'Denied'

		attempt = Attempt(access=attempt_data['access'], api=attempt_data['api'], request=attempt_data['request'], attempt_message=attempt_data['message'])
		db.session.add(attempt)
		db.session.commit()
		return jsonify(return_data)

	api_key = request_data["api_key"]
	# data = request_data['data']

	role_name = ''

	# list of api key present
	roles = Role.query.all()

	for role in roles:

		if bcrypt.check_password_hash(role.hashed_api_key, api_key):
			role_name = role.name
			permissions = role.permissions
			permissions = [permission.name for permission in permissions]

	if role_name:
		return_data['message'] = "Access Denied. You don't have enough permission to create user. Please contact adminstrator to assign permission."
		attempt_data['message'] = "Access Denied. You don't have enough permission to create user. Please contact adminstrator to assign permission."
		return_data['success'] = False
		attempt_data['access'] = 'Denied'

		# check permissions of role
		if 'retrieve_permission' in permissions:
			return_data['message'] = "Access Granted. List of permission with username, email, and role."
			attempt_data['message'] = "Access Granted. List of permission with username, email, and role."
			return_data['success'] = True
			attempt_data['access'] = 'Granted'

			permission_list = Permission.query.all()
			retrieve_permission_list = []

			for permission in permission_list:
				retrieve_permission_list += [permission.name]

			# retrieve_Permission_list = ', '.join(retrieve_permission_list)

			return_data['data'] = retrieve_permission_list

			attempt = Attempt(access=attempt_data['access'], api=attempt_data['api'], request=attempt_data['request'], attempt_message=attempt_data['message'])
			db.session.add(attempt)
			db.session.commit()
			return jsonify(return_data)

		else:
			attempt = Attempt(access=attempt_data['access'], api=attempt_data['api'], request=attempt_data['request'], attempt_message=attempt_data['message'])
			db.session.add(attempt)
			db.session.commit()
			return jsonify(return_data)

	else:
		return_data['message'] = "Access Denied. Please contact adminstrator to get correct api key."
		attempt_data['message'] = "Access Denied. Please contact adminstrator to get correct api key."
		return_data['success'] = False
		attempt_data['access'] = 'Denied'
		# return_data['data'] = request_data

		attempt = Attempt(access=attempt_data['access'], api=attempt_data['api'], request=attempt_data['request'], attempt_message=attempt_data['message'])
		db.session.add(attempt)
		db.session.commit()
		return jsonify(return_data)

# List permissions assigned to a specific role.
@app.route('/permission_per_role')
def permission_per_role():
	# declare variable to be used in the function
	request_data = request.json
	# print(request_data)
	# print(request_data.keys())
	attempt_data = {}
	return_data = {}

	# Log each access attempt with outcomes (granted or denied).
	api = request.base_url
	attempt_data['api'] = str(api)
	attempt_data['request'] = str(request_data)
	attempt_data['access'] = 'Denied'
	attempt_data['message'] = "Access Denied. Please check the format of the request."

	# print(api)
	# request = request_data

	# Access Validation: a) Design APIs to validate whether a user can perform a specific action on a resource based on their assigned roles and permissions.
	if 'api_key' not in list(request_data.keys()):
		return_data['message'] = "Access Denied. Please check the format of the request."
		attempt_data['message'] = "Access Denied. Please check the format of the request."
		return_data['success'] = False
		attempt_data['access'] = 'Denied'

		attempt = Attempt(access=attempt_data['access'], api=attempt_data['api'], request=attempt_data['request'], attempt_message=attempt_data['message'])
		db.session.add(attempt)
		db.session.commit()
		return jsonify(return_data)

	api_key = request_data["api_key"]
	# data = request_data['data']

	role_name = ''

	# list of api key present
	roles = Role.query.all()

	for role in roles:

		if bcrypt.check_password_hash(role.hashed_api_key, api_key):
			role_name = role.name
			permissions = role.permissions
			permissions = [permission.name for permission in permissions]

	if role_name:
		return_data['message'] = "Access Denied. You don't have enough permission list permission assigned to a specific role. Please contact adminstrator to assign permission."
		attempt_data['message'] = "Access Denied. You don't have enough permission list permission assigned to a specific role. Please contact adminstrator to assign permission."
		return_data['success'] = False
		attempt_data['access'] = 'Denied'

		# check permissions of role
		if 'permission_assigned_per_role' in permissions:

			return_data['message'] = "Access Granted. List of permission with role assigned."
			attempt_data['message'] = "Access Granted. List of permission with role assigned."
			return_data['success'] = True
			attempt_data['access'] = 'Granted'

			role_list = Role.query.all()
			retrieve_role_list = []

			for role in role_list:
				role2permission = {}
				role2permission['role_name'] = role.name

				role2permission['role_permission'] = []

				for permission in role.permissions:
					role2permission['role_permission'] += [permission.description]

				role2permission['role_permission'] = ', '.join(role2permission['role_permission'])

				retrieve_role_list.append(role2permission)

			return_data['data'] = retrieve_role_list

			attempt = Attempt(access=attempt_data['access'], api=attempt_data['api'], request=attempt_data['request'], attempt_message=attempt_data['message'])
			db.session.add(attempt)
			db.session.commit()
			return jsonify(return_data)

		else:
			attempt = Attempt(access=attempt_data['access'], api=attempt_data['api'], request=attempt_data['request'], attempt_message=attempt_data['message'])
			db.session.add(attempt)
			db.session.commit()
			return jsonify(return_data)

	else:
		return_data['message'] = "Access Denied. Please contact adminstrator to get correct api key."
		attempt_data['message'] = "Access Denied. Please contact adminstrator to get correct api key."
		return_data['success'] = False
		attempt_data['access'] = 'Denied'
		# return_data['data'] = request_data

		attempt = Attempt(access=attempt_data['access'], api=attempt_data['api'], request=attempt_data['request'], attempt_message=attempt_data['message'])
		db.session.add(attempt)
		db.session.commit()
		return jsonify(return_data)

@app.route("/audit")
def audit():
	# declare variable to be used in the function
	request_data = request.json
	# print(request_data)
	# print(request_data.keys())
	return_data = {}

	# Log each access attempt with outcomes (granted or denied).
	api = request.base_url

	# print(api)
	# request = request_data

	# Access Validation: a) Design APIs to validate whether a user can perform a specific action on a resource based on their assigned roles and permissions.
	if 'api_key' not in list(request_data.keys()):
		return_data['message'] = "Access Denied. Please check the format of the request."
		return_data['success'] = False

		return jsonify(return_data)

	api_key = request_data["api_key"]

	role_name = ''

	# list of api key present
	roles = Role.query.all()

	for role in roles:

		if bcrypt.check_password_hash(role.hashed_api_key, api_key):
			role_name = role.name
			permissions = role.permissions
			permissions = [permission.name for permission in permissions]

	if role_name:
		print(role_name, permissions)
		return_data['message'] = "Access Denied. You don't have enough permission to access Audit Logging. Please contact adminstrator to assign permission."
		return_data['success'] = False

		# check permissions of role
		if 'audit_access' in permissions:
			return_data['message'] = "Access Granted. List of attempts with request and access granted or denied."
			return_data['success'] = True
			attempt_list = Attempt.query.all()
			retrieve_attempt_list = []

			for attempt in attempt_list:
				attempt_dict = {}
				attempt_dict['access'] = attempt.access
				attempt_dict['attempt_time'] = attempt.attempt_time
				attempt_dict['attempt_message'] = attempt.attempt_message
				attempt_dict['api'] = attempt.api
				attempt_dict['request'] = attempt.request
				retrieve_attempt_list.append(attempt_dict)

			return_data['data'] = retrieve_attempt_list
			return jsonify(return_data)

		else:
			return jsonify(return_data)

	else:
		return_data['message'] = "Access Denied. Please contact adminstrator to get correct api key."
		return_data['success'] = False
		# return_data['data'] = request_data
		return jsonify(return_data)


if __name__ == '__main__':
	app.run(debug=True)