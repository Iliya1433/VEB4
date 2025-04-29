from app import app, db, User, Role
from datetime import datetime

def init_db():
    with app.app_context():
        # Создаем таблицы
        db.create_all()
        
        # Создаем роли
        roles = [
            Role(name='Администратор', description='Администратор системы'),
            Role(name='Менеджер', description='Менеджер проекта'),
            Role(name='Пользователь', description='Обычный пользователь')
        ]
        
        for role in roles:
            db.session.add(role)
        db.session.commit()
        
        # Создаем пользователей
        users = [
            {
                'login': 'admin',
                'password': 'Admin123!',
                'first_name': 'Иван',
                'last_name': 'Иванов',
                'middle_name': 'Иванович',
                'role_id': 1  # Администратор
            },
            {
                'login': 'manager',
                'password': 'Manager123!',
                'first_name': 'Петр',
                'last_name': 'Петров',
                'middle_name': 'Петрович',
                'role_id': 2  # Менеджер
            },
            {
                'login': 'user1',
                'password': 'User123!',
                'first_name': 'Сергей',
                'last_name': 'Сергеев',
                'middle_name': 'Сергеевич',
                'role_id': 3  # Пользователь
            },
            {
                'login': 'user2',
                'password': 'User123!',
                'first_name': 'Анна',
                'last_name': 'Смирнова',
                'middle_name': 'Александровна',
                'role_id': 3  # Пользователь
            }
        ]
        
        for user_data in users:
            user = User(
                login=user_data['login'],
                first_name=user_data['first_name'],
                last_name=user_data['last_name'],
                middle_name=user_data['middle_name'],
                role_id=user_data['role_id']
            )
            user.set_password(user_data['password'])
            db.session.add(user)
        
        db.session.commit()
        print("База данных успешно инициализирована!")

if __name__ == '__main__':
    init_db() 