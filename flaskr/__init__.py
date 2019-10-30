import os

from flask import Flask


def create_app(test_config=None):
    """create and configure the app"""
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY='dev',
        DATABASE=os.path.join(app.instance_path, 'flaskr.sqlite')
    )

    if test_config is None:
        # load the instance config, if it exists, when not testing
        app.config.from_pyfile('config.py', silent=True)
    else:
        # load the test config if passed in
        app.config.from_mapping(test_config)

    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    @app.route("/hello")
    def hello():
        return "hello"
    print(app.instance_path)

    from . import db
    db.init_app(app)  # 初始化db

    from . import auth
    app.register_blueprint(auth.bp)  # 注册蓝图 auth

    from . import blog
    app.register_blueprint(blog.bp)  # 注册蓝图 blog
    app.add_url_rule("/", endpoint='index')

    return app


