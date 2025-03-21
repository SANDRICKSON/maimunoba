from flask import render_template, redirect, url_for, flash, request, jsonify, send_file
from flask_login import login_user, logout_user, current_user, login_required
from werkzeug.security import check_password_hash, generate_password_hash
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Message
from extensions import app, mail,db
from werkzeug.utils import secure_filename
#from authlib.integrations.flask_client import OAuth  
from flask_socketio import SocketIO 
import os
from flask_dance.contrib.facebook import make_facebook_blueprint, facebook 
from datetime import datetime
from models import User, ContactMessage
from forms import RegisterForm, MessageForm, LoginForm, UpdateForm, ForgotPasswordForm,ResetPasswordForm, FormUpdateForm
from flask_wtf.csrf import CSRFProtect

csrf = CSRFProtect(app)

socketio = SocketIO(app)

# 📌 Email ვერიფიკაციის ტოკენის გენერაცია
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024  
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}



@app.route("/unread_count")
def unread_count():
    count = Message.query.filter_by(is_read=False).count()
    return jsonify({"unread": count})

# ფუნქცია, რომელიც მომხმარებელს ატყობინებს ახალ შეტყობინებაზე
def notify_admin():
    count = Message.query.filter_by(is_read=False).count()
    socketio.emit("new_message", {"unread": count})

# API შეტყობინების დასამატებლად
@app.route("/add_message")
def add_message():
    new_msg = Message(content="ახალი შეტყობინება")
    db.session.add(new_msg)
    db.session.commit()
    notify_admin()  # ვაგზავნით შეტყობინებას ადმინთან
    return "შეტყობინება დამატებულია!"




oauth = OAuth(app)
oauth.register(
    name="google",
    client_id="489819060653-hio4srkcbmhu0bom757q3tiulo0jmcfp.apps.googleusercontent.com",  # ჩასვი შენი Client ID
    client_secret="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",  # ჩასვი შენი Client Secret
    authorize_url="https://accounts.google.com/o/oauth2/auth",
    authorize_params=None,
    redirect_uri="https://googlevaleri.onrender.com/login/google/callback",
    access_token_url="https://oauth2.googleapis.com/token",
    access_token_params=None,
    refresh_token_url=None,
    client_kwargs={
        "scope": "openid email profile",
        "issuer": "https://accounts.google.com",
        "userinfo_endpoint": "https://openidconnect.googleapis.com/v1/userinfo",
        "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs"
    },
)





facebook_bp = make_facebook_blueprint(client_id='3116224828527575', 
                                       client_secret='a2e4879ae2d44366f3a41650486e4c6e', 
                                       redirect_to='facebook_login')
app.register_blueprint(facebook_bp, url_prefix='/facebook')


@app.route("/google-login")
def google_login():
    return oauth.google.authorize_redirect(url_for("google_callback", _external=True))

@app.route('/facebook_login')
def facebook_login():
    if not facebook.authorized:
        return redirect(url_for('facebook.login'))
    resp = facebook.get('/me')
    assert resp.ok, resp.text
    return 'You are connected with Facebook as: {0}'.format(resp.json()['name'])


@app.route("/login/google/callback")
def google_callback():
    token = oauth.google.authorize_access_token()
    user_info = oauth.google.parse_id_token(token)

    email = user_info.get("email")
    username = user_info.get("name")
    
    user = User.query.filter_by(email=email).first()
    if not user:
        user = User(username=username, email=email, is_verified=True)
        db.session.add(user)
        db.session.commit()

    login_user(user)
    return redirect(url_for("profile"))


@app.after_request
def add_security_headers(response):
    response.headers["X-Frame-Options"] = "DENY"  # ბლოკავს ჩასმას სხვა საიტებზე
    response.headers["X-Content-Type-Options"] = "nosniff"  # MIME type spoofing-ისგან დაცვა
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"  # Referer header-ის კონტროლი
    return response


@app.route("/admin/delete_user/<int:user_id>", methods=["POST"])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        flash("თქვენ არ გაქვთ ამის უფლება!", "danger")
        return redirect(url_for("noadmin"))

    user = User.query.get_or_404(user_id)
    
    if user.username == "sandroqatamadze":  # მთავარ ადმინს ვერ წაშლის
        flash("მთავარი ადმინის წაშლა შეუძლებელია!", "danger")
        return redirect(url_for("view_users"))

    db.session.delete(user)
    db.session.commit()
    flash("მომხმარებელი წარმატებით წაიშალა!", "success")
    return redirect(url_for("view_users"))

@app.route("/admin/make_admin/<int:user_id>", methods=["POST"])
@login_required
def make_admin(user_id):
    if not current_user.is_admin:
        flash("თქვენ არ გაქვთ ამის უფლება!", "danger")
        return redirect(url_for("view_users"))

    user = User.query.get_or_404(user_id)

    if user.is_admin:
        flash("მომხმარებელი უკვე არის ადმინი!", "info")
    else:
        user.is_admin = True
        db.session.commit()
        print(f"User {user.username} is now admin: {user.is_admin}")  # ✅ Debugging

        if user.id == current_user.id:
            login_user(user)  # ხელახლა ავტორიზაცია
            print(f"Logged in user: {current_user.username}, is_admin: {current_user.is_admin}")

        flash(f"{user.username} ახლა არის ადმინი!", "success")

    return redirect(url_for("view_users"))


@app.route("/admin/transfer_admin/<int:user_id>", methods=["POST"])
@login_required
def transfer_admin(user_id):
    if current_user.username != "sandroqatamadze":
        flash("მხოლოდ მთავარ ადმინს შეუძლია უფლებების გადაცემა!", "danger")
        return redirect(url_for("noadmin"))

    user = User.query.get_or_404(user_id)
    
    if user.username == "sandroqatamadze":
        flash("თქვენ უკვე მთავარი ადმინი ხართ!", "info")
        return redirect(url_for("view_users"))

    current_user.username = user.username
 # ძველ ადმინს ჩვეულებრივ იუზერად ცვლის
    user.username = "sandroqatamadze"  # ახალ ადმინს მთავარად ნიშნავს
    db.session.commit()

    flash(f"ადმინისტრაციის გადაცემა დასრულდა! {user.username} ახლა მთავარი ადმინია.", "success")
    return redirect(url_for("view_users"))


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# 📌 Email ვერიფიკაციის ტოკენის გენერაცია
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    form = FormUpdateForm(obj=current_user)
    changed_fields = []

    if form.validate_on_submit():
        if form.username.data != current_user.username:
            changed_fields.append("მომხმარებლის სახელი")
            current_user.username = form.username.data

        if form.email.data != current_user.email:
            changed_fields.append("ელ-ფოსტა")
            current_user.email = form.email.data

        if form.birthday.data != current_user.birthday:
            changed_fields.append("დაბადების თარიღი")
            current_user.birthday = form.birthday.data

        if form.country.data != current_user.country:
            changed_fields.append("ქვეყანა")
            current_user.country = form.country.data

        if form.gender.data != current_user.gender:
            changed_fields.append("სქესი")
            current_user.gender = form.gender.data

        if form.password.data:
            changed_fields.append("პაროლი")
            current_user.password = generate_password_hash(form.password.data)

        # სურათის ატვირთვა
        if 'avatar' in request.files:
            file = request.files['avatar']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                current_user.avatar = filename
                changed_fields.append("პროფილის სურათი")

        db.session.commit()
        
        if changed_fields:
            send_update_notification(current_user, changed_fields)

        flash("მონაცემები წარმატებით განახლდა!", "success")
        return redirect(url_for("profile"))

    return render_template("settings.html", form=form, title="პარამეტრები - მართვის მოწმობა")


def send_update_notification(user, changed_fields):
    """გზავნის შეტყობინებას მომხმარებლის ელფოსტაზე ცვლილებების შესახებ."""
    subject = "თქვენს ანგარიშზე მოხდა ცვლილებები"
    changes = ", ".join(changed_fields)
    
    message_body = f"""
    ძვირფასო {user.username},

    თქვენს ანგარიშზე შეიცვალა შემდეგი მონაცემები: {changes}.

    თუ ეს თქვენ არ გაგიკეთებიათ, დაუყოვნებლივ დაგვიკავშირდით: martvismowmoba937@gmail.com

    პატივისცემით,
    მართვის მოწმობის გუნდი
    """

    msg = Message(
        subject=subject,
        recipients=[user.email],
        body=message_body
    )

    mail.send(msg)


# 📌 პაროლის აღდგენის როუტი
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            token = s.dumps(user.email, salt='password-reset')
            reset_url = url_for('reset_password', token=token, _external=True)
            msg = Message('პაროლის აღდგენა', recipients=[user.email])
            msg.body = f"პაროლის აღსადგენად დააჭირეთ ამ ბმულს: {reset_url}"
            mail.send(msg)
            flash('ელ.ფოსტა გაგზავნილია!', 'success')
            return redirect(url_for('login'))
        else:
            flash('ამ ელ.ფოსტით მომხმარებელი არ მოიძებნა.', 'danger')
    return render_template('forgot_password.html', form=form, title="პაროლის აღდგენა - მართვის მოწმობა")

# 📌 პაროლის განახლების როუტი
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='password-reset', max_age=3600)  # 1 საათი
    except (SignatureExpired, BadTimeSignature):
        flash('ბმული არასწორია ან ვადა გაუვიდა!', 'danger')
        return redirect(url_for('forgot_password'))

    user = User.query.filter_by(email=email).first()
    if not user:
        flash('მომხმარებელი ვერ მოიძებნა!', 'danger')
        return redirect(url_for('forgot_password'))

    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.password = generate_password_hash(form.password.data)
        db.session.commit()
        flash('პაროლი წარმატებით განახლდა!', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html', form=form)

@app.errorhandler(401)
def unauthorized(error):
    return render_template('401.html', title="არაავტორიზირებული მომხმარებელი - მართვის მოწმობა"), 401

@app.errorhandler(500)
def unauthorized(error):
    return render_template('500.html', title="სერვერის შეცდომა - მართვის მოწმობა"), 500

# 502 - Bad Gateway
@app.errorhandler(502)
def bad_gateway(error):
    return render_template('502.html',title="ცუდი კარიბჭე - მართვის მოწმობა"), 502

# 503 - Service Unavailable
@app.errorhandler(503)
def service_unavailable(error):
    return render_template('503.html', title="მიუწვდომელი სერვისი - მართვის მოწმობა"), 503

# 504 - Gateway Timeout
@app.errorhandler(504)
def gateway_timeout(error):
    return render_template('504.html', title="სესიის დრო ამოიწურა -მართვის მოწმობა"), 504

@app.route("/403")
@login_required
def noadmin():
    return render_template("403.html", title="აკრძალული წვდომა - მართვის მოწმობა")


@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html', title="გვერდი არ მოიძებნა - მართვის მოწმობა"), 404

def send_verification_email(user_email):
    token = generate_verification_token(user_email)
    confirm_url = url_for('confirm_email', token=token, _external=True)
    subject = "Email Verification"
    message_body = f"მოგესალმებით, {user.username}! 😊\n\nმადლობა, რომ დაინტერესდით ჩემი პროექტით. თქვენი ანგარიში წარმატებით შეიქმნა! გთხოვთ, გაიარეთ ვერიფიკაცია შემდეგ ბმულზე:\n\n{confirm_url}\n\nმადლობა ყურადღებისთვის! 🙌"



    msg = Message(
        subject=subject,
        recipients=[user_email],
        body=message_body,
        sender="vepkkhistyaosaniproject@gmail.com"  # ✅ დაამატე გამგზავნი!
    )

    mail.send(msg)
def generate_verification_token(email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt='email-confirm')

def confirm_verification_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(token, salt='email-confirm', max_age=expiration)
    except:
        return False
    return email

# 📌 ვერიფიკაციის იმეილის გაგზავნა
def send_verification_email(user_email):
    token = generate_verification_token(user_email)
    confirm_url = url_for('confirm_email', token=token, _external=True)
    subject = "Email Verification"
    message_body = f"მოგესალმებით,! 😊\n\nმადლობა, რომ დაინტერესდით ჩემი პროექტით. თქვენი ანგარიში წარმატებით შეიქმნა! გთხოვთ, გაიარეთ ვერიფიკაცია შემდეგ ბმულზე:\n\n{confirm_url}\n\nმადლობა ყურადღებისთვის! 🙌"

    msg = Message(subject=subject, recipients=[user_email], body=message_body)
    mail.send(msg)

# 📌 ვერიფიკაციის ბმულის დამუშავება
@app.route('/confirm/<token>')
def confirm_email(token):
    email = confirm_verification_token(token)
    if not email:
        flash("ვერიფიკაციის ბმული არასწორია ან ვადა გაუვიდა!", "danger")
        return redirect(url_for('login'))

    user = User.query.filter_by(email=email).first()
    if user and not user.is_verified:
        user.is_verified = True
        user.save()
        flash("თქვენი ემაილი წარმატებით ვერიფიცირდა!", "success")
    elif user and user.is_verified:
        flash("თქვენი ემაილი უკვე ვერიფიცირებულია!", "info")

    return redirect(url_for('login'))

@app.route("/admin/users")
@login_required
def view_users():
    if current_user.username == "sandroqatamadze":
        users = User.query.all()
        return render_template("admin_users.html", users=users, title="მონაცემების ხილვა")
    else:
        flash("Sorry, you are not authorized to view this page.")
        return redirect(url_for('noadmin'))

@app.route("/admin/messages")
@login_required  # მხოლოდ ავტორიზებული მომხმარებლებისთვის
def admin_messages():
    if not current_user.id == 1:  # დარწმუნდი, რომ მომხმარებელი ადმინია
        return "წვდომა აკრძალულია", 403
    
    messages = ContactMessage.query.order_by(ContactMessage.timestamp.desc()).all()
    return render_template("admin_messages.html", messages=messages, title="შეტყობინებები")

@app.route("/admin")
@login_required
def admin():
    if current_user.username == "sandroqatamadze":
        return render_template("admin.html", title="ადმინის გვერდი - მართვის მოწმობა")
    else:
        flash("Sorry but you are not the admin")
        return redirect(url_for('noadmin'))



@app.route("/")
def index():
    return render_template("index.html", title="მთავარი - მართვის მოწმობა")

#def update():
    form = UpdateForm()
    if form.validate_on_submit():
        print(form.update.data)
    return render_template("update.html", form=form, title="გააგრძელე - ვეფხისტყაოსანი")



@app.route("/about")
def about():
    return render_template("about.html", title="პროექტის შესახებ - მართვის მოწმობა")

@app.route("/contact", methods=["GET", "POST"])
def contact():
    return render_template("contact.html",  title="კონტაქტი - მართვის მოწმობა")

@app.route("/ticket")
def tickets():
    return render_template("tickets.html", title="ბილეთები - მართვის მოწმობა")

# 📌 ავტორიზაციის როუტი - მხოლოდ ვერიფიცირებული მომხმარებლებისთვის
@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter(
            (User.username == form.username.data) | (User.email == form.username.data)
        ).first()  # მოძებნის მომხმარებელს სახელით ან ელ-ფოსტით
        
        if user and check_password_hash(user.password, form.password.data):
            if not user.is_verified:
                send_verification_email(user.email)  # ხელახალი ვერიფიკაცია
                flash("თქვენს ელ-ფოსტაზე ვერიფიკაციის ბმული გაგზავნილია!", "warning")
                return redirect(url_for('login'))
            
            login_user(user)
            return redirect(url_for("index")) 

        flash("არასწორი მომხმარებელი ან პაროლი!", "danger")

    return render_template("login.html", form=form, title="ავტორიზაცია - მართვის მოწმობა")



@app.route("/video")
def videos():
    return render_template("video.html", title="ვიდეოები - მართვის მოწმობა")

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route("/profile")
@login_required
def profile():
    return render_template("profile.html", title="პროფილი - მართვის მოწმობა")

# 📌 რეგისტრაციის როუტი - ემაილის ვერიფიკაციის გაგზავნით
@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        user = User(
            username=form.username.data,
            email=form.email.data,
            password=form.password.data,
            birthday=form.birthday.data,
            country=form.country.data,
            gender=form.gender.data,
            is_verified=False
        )
        user.create()
        send_verification_email(user.email)
        flash("თქვენს ელფოსტაზე გაგზავნილია ვერიფიკაციის ბმული!", "info")
        return redirect(url_for("login"))
    
    print(form.errors) 
    return render_template("register.html", form=form, title="რეგისტრაცია - მართვის მოწმობა")


@app.route("/privacy")
def privacy():
    return render_template("privacy.html", title="უსაფრთხოების პოლიტიკა - მართვის მოწმობა")

@app.route("/messages", methods=["GET", "POST"])
@login_required
def messages():
    form = MessageForm()

    if form.validate_on_submit():
        new_message = ContactMessage(
            username=current_user.username,
            user_email=current_user.email,
            message=form.message.data,
        )
        db.session.add(new_message)
        db.session.commit()

        # მომხმარებლის მოპოვება, რომლის აიდიც არის 1
        admin_user = User.query.get(1)
        if admin_user:
            # Email გაგზავნა
            msg = Message(
                subject="ახალი შეტყობინება",
                sender="martvismowmoba937@gmail.com",
                recipients=[admin_user.email],
                body=f"მომხმარებელი: {current_user.username}\n\nშეტყობინება:\n{form.message.data}"
            )
            mail.send(msg)

        flash("შეტყობინება გაგზავნილია!", "success")
        return redirect(url_for("messages"))

    all_messages = ContactMessage.query.order_by(ContactMessage.timestamp.desc()).all()
    
    return render_template("messages.html", messages=all_messages, form=form, title="შეტყობინების გაგზავნა - მართვის მოწმობა")

if __name__ == "__main__":
    app.run(debug=True)