## This project is `Role based two factor authentication using Django Rest Framework`
### Required tools: Python, Django Rest Framework, PostgreSQL, Authenticator App(Authy) and an api client(Postman).
### Other required packages are listed in `requirements.txt` file.

### Setup Instruction:
* Go to the project directory and create a virtual environment using `python -m venv env` command
* Then activate the virtual environment using `source env/bin/activate` command.
* Run this command `pip install -r requirements.txt` to install required packages.
* Go to project directory and run this command `python3 manage.py runserver` to run this app.
* Now open an API platform(Postman) to hit the APIs.

#### Use the app as User:

* Hit `http://localhost:8000/register` with name,email and password in the body part to register as a user.
* After registering hit `http://localhost:8000/login` with valid email and password to login.
* You'll get an **id** and a **secret key** to authenticate your identity.
* Go to **Authenticator App** to get 6 digits otp.
* Now hit `http://localhost:8000/otp/verify` and give the **id** as `user_id` and the **otp** as token in the request body.
* After successful verification you'll get an ` JWT access_token`.
* Now you can hit `http://localhost:8000/protected` with that valid **access_token** in the header. This is a protected url, so without valid token you can not access this route.
* You can reset password by hitting `http://localhost:8000/reset_password`. Provide the jwt access token in the header and give **new_password** value in the body of the request.
#### Use the app as Owner:
* Hit `http://localhost:8000/register/owner` with name, email, password and put role value as **owner**.
* To login and 2-factor authentication follow user's steps.
* After verifying and getting JWT token, hit `http://localhost:8000/owner/show-all` with jwt token in the header to get all info of the users.

