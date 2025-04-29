# Импорт необходимых модулей
# Flask - основной фреймворк для веб-приложения
# render_template - для отображения HTML-шаблонов
# request - для работы с HTTP-запросами
# redirect - для перенаправления
# url_for - для генерации URL
# flash - для отображения сообщений пользователю
from flask import Flask, render_template, request, redirect, url_for, flash

# SQLAlchemy - ORM для работы с базой данных
from flask_sqlalchemy import SQLAlchemy

# Flask-Login - для управления аутентификацией пользователей
# UserMixin - добавляет необходимые методы для работы с пользователями
# login_user - для входа пользователя
# login_required - декоратор для защиты маршрутов
# logout_user - для выхода пользователя
# current_user - для доступа к текущему пользователю
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

# Werkzeug - для работы с паролями
# generate_password_hash - для хеширования паролей
# check_password_hash - для проверки паролей
from werkzeug.security import generate_password_hash, check_password_hash

# datetime - для работы с датами
from datetime import datetime

# re - для работы с регулярными выражениями (валидация)
import re

# Создание экземпляра приложения Flask
app = Flask(__name__)

# Конфигурация приложения
# SECRET_KEY - секретный ключ для сессий и CSRF-защиты
app.config['SECRET_KEY'] = 'your-secret-key'

# Отключаем отслеживание изменений для оптимизации
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# SQLALCHEMY_DATABASE_URI - путь к базе данных SQLite
# sqlite:/// - префикс для SQLite
# users.db - имя файла базы данных
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'

# Инициализация расширений
# SQLAlchemy - для работы с базой данных
db = SQLAlchemy(app)

# В SQLAlchemy связи между таблицами реализуются через три компонента:
# Внешний ключ - определяет физическую связь между таблицами на уровне базы данных. 
# Указывает, какое поле в одной таблице ссылается на поле в другой таблице.
# Отношение - определяет логическую связь между моделями на уровне Python. 
# Позволяет работать со связанными объектами как с атрибутами.
# Обратные ссылки  - это автоматическое создание двусторонней связи между моделями.
# Они позволяют легко получать доступ к связанным объектам из обеих сторон отношения.

# LoginManager - для управления аутентификацией
login_manager = LoginManager()
login_manager.init_app(app)
# Указываем страницу для входа
login_manager.login_view = 'login'

# Модель данных для ролей пользователей
class Role(db.Model):
    # Первичный ключ - уникальный идентификатор роли
    id = db.Column(db.Integer, primary_key=True)
    
    # Название роли (не может быть пустым)
    name = db.Column(db.String(50), nullable=False)
    
    # Описание роли (может быть пустым)
    description = db.Column(db.String(200))
    
    # Связь с пользователями (один-ко-многим)
    # backref='role' - создает обратную ссылку в модели User
    # lazy=True - загрузка связанных объектов только при обращении
    users = db.relationship('User', backref='role', lazy=True)

# Модель данных для пользователей
class User(UserMixin, db.Model):
    # Первичный ключ - уникальный идентификатор пользователя
    id = db.Column(db.Integer, primary_key=True)
    
    # Уникальный логин пользователя (не может быть пустым)
    login = db.Column(db.String(50), unique=True, nullable=False)
    
    # Хеш пароля (не может быть пустым)
    password_hash = db.Column(db.String(128), nullable=False)
    
    # Фамилия (может быть пустой)
    last_name = db.Column(db.String(50))
    
    # Имя (обязательное поле)
    first_name = db.Column(db.String(50), nullable=False)
    
    # Отчество (может быть пустым)
    middle_name = db.Column(db.String(50))
    
    # Ссылка на роль пользователя
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'))
    
    # Дата создания записи (устанавливается автоматически)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Метод для установки пароля
    # Генерирует хеш пароля и сохраняет его
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    # Метод для проверки пароля
    # Сравнивает введенный пароль с хешем в базе
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Функция загрузки пользователя для Flask-Login
# Вызывается при каждой аутентификации
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Функция валидации логина
# Проверяет соответствие логина требованиям
def validate_login(login):
    # Проверка на пустое значение
    if not login:
        return False, "Поле не может быть пустым"
    
    # Проверка минимальной длины
    if len(login) < 5:
        return False, "Логин должен содержать не менее 5 символов"
    
    # Проверка на допустимые символы (только латинские буквы и цифры)
    if not re.match(r'^[a-zA-Z0-9]+$', login):
        return False, "Логин должен содержать только латинские буквы и цифры"
    
    return True, ""

# Функция валидации пароля
# Проверяет соответствие пароля требованиям безопасности
def validate_password(password):
    # Проверка на пустое значение
    if not password:
        return False, "Поле не может быть пустым"
    
    # Проверка минимальной длины
    if len(password) < 8:
        return False, "Пароль должен содержать не менее 8 символов"
    
    # Проверка максимальной длины
    if len(password) > 128:
        return False, "Пароль должен содержать не более 128 символов"
    
    # Проверка наличия заглавной буквы
    if not re.search(r'[A-Z]', password):
        return False, "Пароль должен содержать хотя бы одну заглавную букву"
    
    # Проверка наличия строчной буквы
    if not re.search(r'[a-z]', password):
        return False, "Пароль должен содержать хотя бы одну строчную букву"
    
    # Проверка наличия цифры
    if not re.search(r'[0-9]', password):
        return False, "Пароль должен содержать хотя бы одну цифру"
    
    # Проверка на отсутствие пробелов
    if re.search(r'\s', password):
        return False, "Пароль не должен содержать пробелы"
    
    # Проверка на допустимые символы
    if not re.match(r'^[a-zA-Zа-яА-Я0-9~!?@#$%^&*_\-+()\[\]{}><\/\\|"\',.:;]+$', password):
        return False, "Пароль содержит недопустимые символы"
    
    return True, ""

# Маршрут главной страницы
@app.route('/')
def index():
    # Получаем всех пользователей из базы данных
    users = User.query.all()
    # Отображаем шаблон с списком пользователей
    return render_template('index.html', users=users)

# Маршрут страницы входа
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Получаем данные из формы
        login = request.form.get('login')
        password = request.form.get('password')
        
        # Ищем пользователя по логину
        user = User.query.filter_by(login=login).first()
        
        # Проверяем существование пользователя и правильность пароля
        if user and user.check_password(password):
            # Выполняем вход пользователя
            login_user(user)
            # Перенаправляем на главную страницу
            return redirect(url_for('index'))
        
        # Если вход не удался, показываем сообщение об ошибке
        flash('Неверный логин или пароль')
    
    # Отображаем форму входа
    return render_template('login.html')

# Маршрут выхода из системы
@app.route('/logout')
@login_required  # Требуется авторизация
def logout():
    # Выполняем выход пользователя
    logout_user()
    # Перенаправляем на главную страницу
    return redirect(url_for('index'))

# Маршрут просмотра данных пользователя
@app.route('/user/<int:user_id>')
def view_user(user_id):
    # Получаем пользователя по ID или возвращаем 404
    user = User.query.get_or_404(user_id)
    # Отображаем страницу с данными пользователя
    return render_template('view_user.html', user=user)

# Маршрут создания нового пользователя
@app.route('/user/create', methods=['GET', 'POST'])
@login_required  # Требуется авторизация
def create_user():
    # Получаем список всех ролей для выпадающего списка
    roles = Role.query.all()
    
    if request.method == 'POST':
        # Получаем данные из формы
        login = request.form.get('login')
        password = request.form.get('password')
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        middle_name = request.form.get('middle_name')
        role_id = request.form.get('role_id')

        # Валидация данных
        login_valid, login_error = validate_login(login)
        password_valid, password_error = validate_password(password)
        
        # Если есть ошибки валидации
        if not login_valid or not password_valid:
            if not login_valid:
                flash(login_error)
            if not password_valid:
                flash(password_error)
            # Возвращаем форму с введенными данными
            return render_template('user_form.html', 
                                 login=login,
                                 first_name=first_name,
                                 last_name=last_name,
                                 middle_name=middle_name,
                                 role_id=role_id,
                                 roles=roles)

        try:
            # Создаем нового пользователя
            user = User(login=login,
                       first_name=first_name,
                       last_name=last_name,
                       middle_name=middle_name,
                       role_id=role_id)
            # Устанавливаем пароль
            user.set_password(password)
            # Добавляем пользователя в сессию
            db.session.add(user)
            # Сохраняем изменения в базе
            db.session.commit()
            # Показываем сообщение об успехе
            flash('Пользователь успешно создан')
            # Перенаправляем на главную страницу
            return redirect(url_for('index'))
        except Exception as e:
            # В случае ошибки откатываем изменения
            db.session.rollback()
            # Показываем сообщение об ошибке
            flash('Ошибка при создании пользователя')
            # Возвращаем форму с введенными данными
            return render_template('user_form.html',
                                 login=login,
                                 first_name=first_name,
                                 last_name=last_name,
                                 middle_name=middle_name,
                                 role_id=role_id,
                                 roles=roles)
    
    # Отображаем форму создания пользователя
    return render_template('user_form.html', roles=roles)

# Маршрут редактирования пользователя
@app.route('/user/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required  # Требуется авторизация
def edit_user(user_id):
    # Получаем пользователя по ID или возвращаем 404
    user = User.query.get_or_404(user_id)
    # Получаем список всех ролей
    roles = Role.query.all()
    
    if request.method == 'POST':
        # Обновляем данные пользователя
        user.first_name = request.form.get('first_name')
        user.last_name = request.form.get('last_name')
        user.middle_name = request.form.get('middle_name')
        user.role_id = request.form.get('role_id')

        try:
            # Сохраняем изменения в базе
            db.session.commit()
            # Показываем сообщение об успехе
            flash('Пользователь успешно обновлен')
            # Перенаправляем на главную страницу
            return redirect(url_for('index'))
        except Exception as e:
            # В случае ошибки откатываем изменения
            db.session.rollback()
            # Показываем сообщение об ошибке
            flash('Ошибка при обновлении пользователя')
            # Возвращаем форму с данными пользователя
            return render_template('user_form.html', user=user, roles=roles)
    
    # Отображаем форму редактирования
    return render_template('user_form.html', user=user, roles=roles)

# Маршрут удаления пользователя
@app.route('/user/<int:user_id>/delete', methods=['POST'])
@login_required  # Требуется авторизация
def delete_user(user_id):
    # Получаем пользователя по ID или возвращаем 404
    user = User.query.get_or_404(user_id)
    try:
        # Удаляем пользователя
        db.session.delete(user)
        # Сохраняем изменения в базе
        db.session.commit()
        # Показываем сообщение об успехе
        flash('Пользователь успешно удален')
    except Exception as e:
        # В случае ошибки откатываем изменения
        db.session.rollback()
        # Показываем сообщение об ошибке
        flash('Ошибка при удалении пользователя')
    # Перенаправляем на главную страницу
    return redirect(url_for('index'))

# Маршрут изменения пароля
@app.route('/change-password', methods=['GET', 'POST'])
@login_required  # Требуется авторизация
def change_password():
    if request.method == 'POST':
        # Получаем данные из формы
        old_password = request.form.get('old_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        # Проверяем текущий пароль
        if not current_user.check_password(old_password):
            flash('Неверный текущий пароль')
            return render_template('change_password.html')

        # Проверяем совпадение новых паролей
        if new_password != confirm_password:
            flash('Новые пароли не совпадают')
            return render_template('change_password.html')

        # Валидируем новый пароль
        password_valid, password_error = validate_password(new_password)
        if not password_valid:
            flash(password_error)
            return render_template('change_password.html')

        try:
            # Устанавливаем новый пароль
            current_user.set_password(new_password)
            # Сохраняем изменения в базе
            db.session.commit()
            # Показываем сообщение об успехе
            flash('Пароль успешно изменен')
            # Перенаправляем на главную страницу
            return redirect(url_for('index'))
        except Exception as e:
            # В случае ошибки откатываем изменения
            db.session.rollback()
            # Показываем сообщение об ошибке
            flash('Ошибка при изменении пароля')
            return render_template('change_password.html')

    # Отображаем форму изменения пароля
    return render_template('change_password.html')

# Точка входа в приложение
if __name__ == '__main__':
    with app.app_context():
        # Создаем таблицы в БД при первом запуске
        db.create_all()
    # Запускаем приложение в режиме отладки
    app.run(debug=True) 