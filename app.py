from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Length
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import requests
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24).hex()
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5 MB
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg'}

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

os.makedirs(os.path.join(app.root_path, app.config['UPLOAD_FOLDER']), exist_ok=True)

API_URL = "https://api-inference.huggingface.co/models/csebuetnlp/mT5_multilingual_XLSum "
HF_TOKEN = "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"  # Тут надо как-то скрыть токен, но я не умею
headers = {"Authorization": f"Bearer {HF_TOKEN}"}

# функции для проверки файлов
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Генерация тезисов через HuggingFace API
def generate_summary(text):
    if len(text.split()) < 20:
        return text[:200] + '...' if len(text) > 200 else text

    payload = {
        "inputs": text,
        "parameters": {
            "max_length": 100,
            "min_length": 30,
            "do_sample": False
        }
    }

    try:
        response = requests.post(API_URL, headers=headers, json=payload, timeout=10)
        result = response.json()
        if isinstance(result, list) and "summary_text" in result[0]:
            return result[0]["summary_text"]
        else:
            print("Ошибка API:", result)
            return text[:200] + '...'
    except Exception as e:
        print("Ошибка запроса:", e)
        return text[:200] + '...'


# Модели
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    posts = db.relationship('Post', backref='author', lazy=True)
    avatar_filename = db.Column(db.String(255))

    @property
    def password(self):
        raise AttributeError('Пароль не доступен для чтения')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    image_filename = db.Column(db.String(255))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    summary = db.Column(db.Text)

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    post = db.relationship('Post', backref='comments')
    author = db.relationship('User', backref='comments')

# Формы
class RegisterForm(FlaskForm):
    username = StringField('Имя пользователя', validators=[DataRequired(), Length(min=4, max=50)])
    password = PasswordField('Пароль', validators=[DataRequired(), Length(min=6)])
    submit = SubmitField('Зарегистрироваться')


class LoginForm(FlaskForm):
    username = StringField('Имя пользователя', validators=[DataRequired()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    submit = SubmitField('Войти')


class PostForm(FlaskForm):
    title = StringField('Заголовок', validators=[DataRequired(), Length(max=100)])
    content = TextAreaField('Текст поста', validators=[DataRequired()])
    submit = SubmitField('Опубликовать')

class CommentForm(FlaskForm):
    content = TextAreaField('Ваш комментарий', validators=[DataRequired(), Length(max=500)])
    submit = SubmitField('Отправить')

# Загрузчик пользователя
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# Маршруты
@app.route('/')
def index():
    posts = Post.query.order_by(Post.created_at.desc()).all()
    return render_template('index.html', posts=posts)

@app.route('/profile/<username>')
def profile(username):
    user = User.query.filter_by(username=username).first_or_404()
    posts = Post.query.filter_by(author=user).order_by(Post.created_at.desc()).all()
    return render_template('profile.html', user=user, posts=posts)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(username=form.username.data).first()
        if existing_user:
            flash('Данный логин уже занят', 'danger')
            return render_template('register.html', form=form)

        user = User(username=form.username.data)
        user.password = form.password.data
        db.session.add(user)
        db.session.commit()
        flash('Регистрация прошла успешно! Теперь вы можете войти.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.verify_password(form.password.data):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
        flash('Неверное имя пользователя или пароль', 'danger')
    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/create_post', methods=['GET', 'POST'])
@login_required
def create_post():
    form = PostForm()
    error = None
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        file = request.files.get('image')

        if not title or not content:
            flash('Заполните все поля!', 'danger')
        else:
            image_filename = None
            if file and file.filename != '':
                if not allowed_file(file.filename):
                    error = 'Недопустимый формат файла. Допустимые: png, jpg, jpeg.'
                elif request.content_length > app.config['MAX_CONTENT_LENGTH']:
                    error = 'Файл слишком большой. Максимум: 5 МБ.'
                else:
                    filename = file.filename
                    upload_folder = app.config['UPLOAD_FOLDER']
                    file.save(os.path.join(app.root_path, upload_folder, filename))
                    image_filename = filename

            summary = generate_summary(content)

            if not error:
                post = Post(
                    title=title,
                    content=content,
                    author=current_user,
                    image_filename=image_filename,
                    summary=summary
                )
                db.session.add(post)
                db.session.commit()
                flash('Пост успешно опубликован!', 'success')
                return redirect(url_for('index'))

    return render_template('create_post.html', form=form, error=error)


@app.route('/delete_post/<int:post_id>', methods=['POST'])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author != current_user:
        abort(403)
    db.session.delete(post)
    db.session.commit()
    flash('Пост успешно удален!', 'success')
    return redirect(url_for('index'))

@app.route('/search')
def search():
    query = request.args.get('q', '').strip()
    if not query:
        flash("Введите запрос для поиска", "warning")
        return redirect(url_for('index'))
    # Поисковик по заголовкам и тезисам
    results = Post.query.filter(
        db.or_(
            Post.title.contains(query),
            Post.summary.contains(query)
        )
    ).order_by(Post.created_at.desc()).all()

    return render_template('search_results.html', results=results, query=query)

@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    error = None
    avatar_url = url_for('static', filename='uploads/avatars/' + (current_user.avatar_filename or 'default.png'))

    if request.method == 'POST':
        file = request.files.get('avatar')

        if not file or file.filename == '':
            error = 'Файл не выбран'
        elif file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.root_path, 'static/uploads/avatars', filename))
            current_user.avatar_filename = filename
            db.session.commit()
            flash('Аватар успешно обновлен!', 'success')
            return redirect(url_for('profile', username=current_user.username))
        else:
            error = 'Недопустимый формат файла'

    return render_template('edit_profile.html', avatar_url=avatar_url, error=error)

@app.route('/post/<int:post_id>', methods=['GET', 'POST'])
def view_post(post_id):
    post = Post.query.get_or_404(post_id)
    comment_form = CommentForm()

    if comment_form.validate_on_submit():
        if not current_user.is_authenticated:
            flash('Войдите, чтобы оставить комментарий.', 'danger')
            return redirect(url_for('login'))

        new_comment = Comment(
            content=comment_form.content.data,
            post=post,
            author=current_user
        )
        db.session.add(new_comment)
        db.session.commit()
        flash('Комментарий успешно опубликован!', 'success')
        return redirect(url_for('view_post', post_id=post.id))

    return render_template('post.html', post=post, comment_form=comment_form)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Проверки бд
        try:
            db.session.query(User.avatar_filename).limit(1).all()
        except Exception as e:
            if "no such column" in str(e):
                with app.app_context():
                    db.engine.execute("ALTER TABLE user ADD COLUMN avatar_filename VARCHAR(255)")
                    db.session.commit()

        try:
            db.session.query(Post.summary).limit(1).all()
        except Exception as e:
            if "no such column" in str(e):
                db.engine.execute("ALTER TABLE post ADD COLUMN summary TEXT")
                db.session.commit()

    app.run(debug=True)