from crbac import app, db, User, Role, Permission, Attempt, role_permission, user_role, bcrypt

def db_setup():

	# create session
	app.app_context().push()

	# drop all the database
	db.drop_all()
	print('[Log] : Removed Previous Database.')

	# create new tables
	db.create_all()
	print('[Log] : Created Tables.')

	# create users admin, supervisor, staff
	user_1 = User(username='admin', email='admin@company.com')
	user_2 = User(username='supervisor', email='supervisor@company.com')
	user_3 = User(username='staff', email='staff@company.com')

	db.session.add_all([user_1, user_2, user_3])
	db.session.commit()
	print('[Log] : Added Users.')

	# create permissions
	permission_1 = Permission(description='Create users', name='create_users')
	permission_2 = Permission(description='Retrieve user lists', name='retrieve_user_list')
	permission_3 = Permission(description='Assign predefined roles (staff, supervisor, admin) to users', name='assign_user_role')
	permission_4 = Permission(description='Retrieve the list of roles', name='retrieve_roles')
	permission_5 = Permission(description='Dynamically assign permissions to these roles', name='assign_permission')
	permission_6 = Permission(description='List all available permissions', name='retrieve_permission')
	permission_7 = Permission(description='List permissions assigned to a specific role', name='permission_assigned_per_role')
	permission_8 = Permission(description='Log each access attempt with outcomes (granted or denied)', name='audit_access')

	db.session.add_all([permission_1, permission_2, permission_3, permission_4, permission_5, permission_6, permission_7, permission_8])
	db.session.commit()
	print('[Log] : Added Permissions.')

	# 3 api keys - admin, supervisor, staff
	admin_api_key = '1ec2e61c120d3fa819f211a980badb8b'
	supervisor_api_key = '29f9c4061b9d72803c02cfd2e89c94e7'
	staff_api_key = 'd09c3e948f5a38433d89051e64cda0ea'

	# hashed api keys
	admin_hashed_api_key = bcrypt.generate_password_hash(admin_api_key)
	supervisor_hashed_api_key = bcrypt.generate_password_hash(supervisor_api_key)
	staff_hashed_api_key = bcrypt.generate_password_hash(staff_api_key)

	# create roles
	role_1= Role(name='admin', hashed_api_key=admin_hashed_api_key, permissions=Permission.query.all(), users=[user_1])
	role_2 = Role(name='supervisor', hashed_api_key=supervisor_hashed_api_key, permissions=[permission_1, permission_2, permission_4, permission_6, permission_7], users=[user_2])
	role_3 = Role(name='staff', hashed_api_key=staff_hashed_api_key, permissions=[permission_2, permission_4, permission_6], users=[user_3])

	db.session.add_all([role_1, role_2, role_3])
	db.session.commit()
	print('[Log] : Added Roles.')

if __name__ == '__main__':
	db_setup()