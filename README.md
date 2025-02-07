# Role-Based Access Control (RBAC) system

## [Postman Collection Link](https://www.postman.com/gauravchopracg/workspace/development/collection/6438205-deeac2e3-9701-414b-8e0f-d977edeec13c?action=share&creator=6438205)

## Setup Instructions
**The following commands has been reproduced on aws ec2 instance Ubuntu 24.04.1 LTS**

1. Install python, supervisor, nginx and git
```
sudo apt-get -y update
sudo apt-get -y install python3 python3-venv python3-dev
sudo apt-get -y install supervisor nginx git
```

2. Clone the github repo
```
git clone https://github.com/gauravchopracg/custom_role_based_access_control_system.git
cd custom_role_based_access_control_system
```

3. Create a virtual environment by running the command
```
python3 -m venv venv
source venv/bin/activate
```

4. Install the libraries in requirements.txt and install gunicorn
```
pip install -r requirements.txt
pip install gunicorn
```

5. Setup database, api key with pre-defined roles and permissions
```
python3 db_setup.py
```

6. Check gunicorn server by enabing 5000 port on security group in AWS and running this command
```
gunicorn -b 0.0.0.0:5000 -w 4 crbac:app
```

7. Create a configuration file in /etc/supervisor/conf.d.
```
[program:custom_role_based_access_control_system]
command=/home/ubuntu/custom_role_based_access_control_system/venv/bin/gunicorn -b 0.0.0.0:5000 -w 4 crbac:app
directory=/home/ubuntu/custom_role_based_access_control_system
user=ubuntu
autostart=true
autorestart=true
stopasgroup=true
killasgroup=true
```

8. After you write this configuration file, you have to reload the supervisor service for it to be imported:
```
sudo supervisorctl reload
```

9. Open the browser and check ip_address:port_5000

## Deployment Links
AWS EC2 Machine IP address: 18.246.227.19

1. Create users : 18.246.227.19:5000/users/register
2. Retrieve user lists : 18.246.227.19:5000/users
3. Assign predefined roles (staff, supervisor, admin) to users : 18.246.227.19:5000/users/assign_role/2
4. Retrieve the list of roles : 18.246.227.19:5000/roles
5. Dynamically assign permissions to these roles. Only Admin should have the ability to assign permissions : 18.246.227.19:5000/permissions
6. List all available permissions : 18.246.227.19:5000/permission_per_role

## Other Relevant Information
1. User Management: Manage users and assign roles.
2. Role Management: Roles are predefined (staff, supervisor, admin).
3. Permission Management: Dynamically associate permissions with roles and resources.
4. Access Validation: Validate whether a user has specific permissions to perform an action on a resource.
5. [Bonus] Audit Logging: Log access attempts and their outcomes (granted/denied).