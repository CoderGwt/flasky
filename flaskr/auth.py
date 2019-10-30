import functools

from flask import Blueprint, flash, g, \
    redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from flaskr.db import get_db

bp = Blueprint("auth", __name__, url_prefix='/auth')  # 创建蓝图（须注册后才能使用）


@bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get("username")
        password = request.form.get("password")
        db = get_db()
        error = None

        if not username:  # 用户名是否为空
            error = "Username is required"
        elif not password:  # 密码是否为空
            error = "Password is required"
        # 用户名是否已经被注册
        elif db.execute('select id from user where username = ?', (username, )).fetchone() is not None:
            error = "User {} is already registered".format(username)

        # 如果没有错误，则注册用户信息，并重定向到登录界面
        if error is None:
            db.execute("insert into user (username, password) values (? ,? )",
                       (username, generate_password_hash(password)))
            db.commit()
            return redirect(url_for('auth.login'))
        flash(error)
    return render_template('auth/register.html')


@bp.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()  # 获取到数据库连接
        error = None

        # 查询用户信息
        user = db.execute('select * from user where username = ?', (username, )).fetchone()
        print("user 的 type：", type(user))
        if not user:
            error = "Incorrect username"
        elif not check_password_hash(user['password'], password):
            error = "Incorrect password"

        if error is None:
            session.clear()
            session['user_id'] = user['id']
            return redirect(url_for('index'))
        flash(error)

    return render_template('auth/login.html')


@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')
    if not user_id:
        g.user = None
    else:
        g.user = get_db().execute('select * from user where id = ?', (user_id, )).fetchone()


@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))
        return view(**kwargs)
    return wrapped_view










