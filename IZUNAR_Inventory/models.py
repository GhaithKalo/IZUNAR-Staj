from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
from zoneinfo import ZoneInfo

db = SQLAlchemy()
turkey_tz = ZoneInfo("Europe/Istanbul")

# Association table (çoktan-çoğa ilişki) Component <-> Tag
component_tag = db.Table(
    'component_tag',
    db.Column('component_id', db.Integer, db.ForeignKey('component.id'), primary_key=True),
    db.Column('tag_id', db.Integer, db.ForeignKey('tag.id'), primary_key=True)
)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), default="user")  # 'admin' veya 'user'
    can_add_product = db.Column(db.Boolean, default=False)

    @property
    def is_admin(self):
        return self.role == 'admin'

class Tag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)

    components = db.relationship(
        'Component',
        secondary=component_tag,
        back_populates='tags'
    )

class Component(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    type = db.Column(db.String(100), nullable=True)
    location = db.Column(db.String(150), nullable=True)
    description = db.Column(db.Text, nullable=True)
    quantity = db.Column(db.Integer, nullable=False)
    image_url = db.Column(db.String(300), default="https://via.placeholder.com/300x200?text=Ürün")
    part_number = db.Column(db.String(100), nullable=True)
    code = db.Column(db.String(150), unique=True)

    tags = db.relationship(
        'Tag',
        secondary=component_tag,
        back_populates='components'
    )

class ComponentLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    comp_id = db.Column(db.Integer, db.ForeignKey("component.id"))
    action = db.Column(db.String(50))  # örn: 'borrow', 'return', 'increase', 'decrease'
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(turkey_tz))
    amount = db.Column(db.Integer, default=1)

    user = db.relationship("User", backref="logs")
    component = db.relationship("Component")

class BorrowLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    comp_id = db.Column(db.Integer, db.ForeignKey('component.id'), nullable=False)
    action = db.Column(db.String(10), nullable=False)  # "borrow", "return", veya "consume"
    amount = db.Column(db.Integer, nullable=False)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(turkey_tz), nullable=False)

    user = db.relationship('User', backref=db.backref('borrow_logs', lazy=True))
    component = db.relationship('Component', backref=db.backref('borrow_logs', lazy=True))

class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    location = db.Column(db.String(100), nullable=True)
    status = db.Column(db.String(20), default="Bekliyor")  # "Bekliyor", "Onaylandı", "Tamamlandı"
    approved = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(turkey_tz))

    user = db.relationship('User', backref='projects')
    items = db.relationship('ProjectItem', backref='project', cascade="all, delete-orphan")

class ProjectItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    comp_id = db.Column(db.Integer, db.ForeignKey('component.id'), nullable=False)
    amount = db.Column(db.Integer, nullable=False)

    component = db.relationship('Component')

