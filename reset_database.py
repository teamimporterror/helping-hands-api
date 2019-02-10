from app import bcrypt
from app.models import db, AdminModel


def reset_database():
    password_hash = bcrypt.generate_password_hash("admin123").decode('utf-8')
    admin = AdminModel(username="admin", password_hash=password_hash)

    db.session.commit()
    db.drop_all()
    db.create_all()
    db.session.add(admin)
    db.session.commit()
    print('done')


if __name__ == '__main__':
    reset_database()
