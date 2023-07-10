from flask import Flask, render_template, request, redirect, url_for, flash
from flask_bootstrap import Bootstrap

import pyotp

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret'
Bootstrap(app)


@app.route('/')
def index():
    return '<h1>Hello world</h1>'


@app.route('/login')
def login():
    return render_template('login.html')


@app.route('/login', methods=['POST'])
def login_post():
    creds = {
        'username': 'admin',
        'password': 'admin'
    }

    username = request.form.get('username')
    password = request.form.get('password')
    if username == creds['username'] and password == creds['password']:
        flash('Login success', 'success')
        return redirect(url_for('login_2fa'))
    else:
        flash('Login failed', 'danger')
        return redirect(url_for('login'))


# 2FA page route
@app.route("/login/2fa/")
def login_2fa():
    # generating random secret key for authentication
    secret = pyotp.random_base32()
    return render_template("login_2fa.html", secret=secret)


@app.route("/login/2fa/", methods=["POST"])
def login_2fa_form():
    # getting secret key used by user
    secret = request.form.get("secret")
    # getting OTP provided by user
    otp = int(request.form.get("otp"))

    # verifying submitted OTP with PyOTP
    if pyotp.TOTP(secret).verify(otp):
        # inform users if OTP is valid
        flash("The TOTP 2FA token is valid", "success")
        return redirect(url_for("login_2fa"))
    else:
        # inform users if OTP is invalid
        flash("You have supplied an invalid 2FA token!", "danger")
        return redirect(url_for("login_2fa"))


if __name__ == '__main__':
    app.run(debug=True)
