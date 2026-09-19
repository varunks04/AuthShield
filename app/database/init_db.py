"""Database initialization and seeding script for AuthShield."""

from sqlalchemy.orm import Session
from app.database.connection import engine, SessionLocal, Base
from app.models.role import Role, Permission
from app.models.user import User
from app.models.audit import AuditLog
from app.models.alert import SecurityAlert
from app.auth.password import hash_password


def init_db(db: Session = None):
    """Initializes tables and populates default roles and seed users."""
    Base.metadata.create_all(bind=engine)

    close_session = False
    if db is None:
        db = SessionLocal()
        close_session = True

    try:
        # Seed Roles
        role_definitions = [
            ("user", "Standard application user with access to personal resources"),
            ("analyst", "Security analyst with monitoring and alert investigation permissions"),
            ("admin", "System administrator with full user and role management authority"),
        ]

        roles = {}
        for role_name, description in role_definitions:
            role = db.query(Role).filter(Role.name == role_name).first()
            if not role:
                role = Role(name=role_name, description=description)
                db.add(role)
                db.commit()
                db.refresh(role)
            roles[role_name] = role

        # Seed Users
        seed_users = [
            {
                "username": "admin",
                "email": "admin@authshield.io",
                "password": "AdminPassword123!",
                "role": roles["admin"],
                "status": "active"
            },
            {
                "username": "analyst",
                "email": "analyst@authshield.io",
                "password": "AnalystPassword123!",
                "role": roles["analyst"],
                "status": "active"
            },
            {
                "username": "user",
                "email": "user@authshield.io",
                "password": "UserPassword123!",
                "role": roles["user"],
                "status": "active"
            },
            {
                "username": "disabled_user",
                "email": "disabled@authshield.io",
                "password": "DisabledPassword123!",
                "role": roles["user"],
                "status": "disabled"
            }
        ]

        for user_data in seed_users:
            existing = db.query(User).filter(User.username == user_data["username"]).first()
            if not existing:
                new_user = User(
                    username=user_data["username"],
                    email=user_data["email"],
                    password_hash=hash_password(user_data["password"]),
                    role_id=user_data["role"].id,
                    status=user_data["status"]
                )
                db.add(new_user)
        db.commit()

    finally:
        if close_session:
            db.close()


if __name__ == "__main__":
    print("Initializing AuthShield database...")
    init_db()
    print("Database initialization complete.")
