from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, Component, BorrowLog, Project, ProjectItem, Tag, Request
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
from flask_migrate import Migrate
from werkzeug.utils import secure_filename
from sqlalchemy import func, or_
from collections import defaultdict
from zoneinfo import ZoneInfo
from flask_wtf import CSRFProtect
from flask_wtf.csrf import generate_csrf
import os, re

app = Flask(__name__, static_folder='static')
app.secret_key = 'AmpeatleSupremacy'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(os.path.abspath(os.path.dirname(__file__)), 'instance', 'database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
csrf = CSRFProtect()
csrf.init_app(app)

# Fotoğraf yükleme ayarları
UPLOAD_FOLDER = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'static', 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2 MB sınır

# Veritabanı ve migrate ayarları
db.init_app(app)
migrate = Migrate(app, db)

# Login yöneticisi
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=generate_csrf())

@app.context_processor
def inject_timezone():
    return dict(tz=ZoneInfo("Europe/Istanbul"))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
@login_required
def index():
    search_query = request.args.get('q', '').strip()

    components = Component.query.filter(
        or_(
            Component.name.ilike(f'%{search_query}%'),
            Component.type.ilike(f'%{search_query}%'),
            Component.code.ilike(f'%{search_query}%')  # Ürün kodu ile arama eklendi
        )
    ).all() if search_query else Component.query.all()

    grouped_components = defaultdict(list)
    for comp in components:
        grouped_components[comp.type or 'Diğer'].append(comp)

    all_types = [] if search_query else sorted(
        [t[0] or 'Diğer' for t in db.session.query(Component.type).distinct().all()]
    )

    return render_template('index.html', grouped_components=grouped_components, all_types=all_types, search_query=search_query)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and check_password_hash(user.password, request.form['password']):
            login_user(user)
            return redirect(url_for('index'))
        flash("Geçersiz kullanıcı adı veya şifre")
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        if not username or not password:
            flash("Kullanıcı adı ve şifre boş olamaz.")
            return render_template('register.html')
        if User.query.filter_by(username=username).first():
            flash("Bu kullanıcı adı zaten kullanılıyor.")
            return render_template('register.html')
        hashed_pw = generate_password_hash(password)
        new_user = User(username=username, password=hashed_pw, can_add_product=False)
        db.session.add(new_user)
        db.session.commit()
        flash("Kayıt başarılı. Giriş yapabilirsiniz.")
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    # admin dashboard içeriği
    return render_template('admin/dashboard.html')

@app.route('/admin/users')
@login_required
def manage_users():
    if not current_user.is_admin:
        abort(403)
    users = User.query.all()
    return render_template('admin/manage_users.html', users=users)

@app.route('/admin/users/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if not current_user.is_admin:
        abort(403)
    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        role = request.form.get('role')
        new_password = request.form.get('new_password')
        new_password2 = request.form.get('new_password2')
        if role in ['user', 'admin']:
            user.role = role
        if new_password:
            if not new_password2 or new_password != new_password2:
                flash("Şifreler eşleşmiyor veya boş.", "danger")
                return redirect(url_for('edit_user', user_id=user.id))
            user.password = generate_password_hash(new_password)
        db.session.commit()
        flash("Kullanıcı güncellendi.", "success")
        return redirect(url_for('manage_users'))
    return render_template('admin/edit_user.html', user=user)

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        old_password = request.form.get('old_password')
        new_password = request.form.get('new_password')
        new_password2 = request.form.get('new_password2')
        if not check_password_hash(current_user.password, old_password):
            flash("Mevcut şifreniz yanlış.", "danger")
        elif not new_password or new_password != new_password2:
            flash("Yeni şifreler eşleşmiyor veya boş.", "danger")
        else:
            current_user.password = generate_password_hash(new_password)
            db.session.commit()
            flash("Şifreniz güncellendi.", "success")
            return redirect(url_for('index'))
    return render_template('change_password.html')

@app.route('/admin/users/add', methods=['GET', 'POST'])
@login_required
def add_user():
    if not current_user.is_admin:
        flash("Bu sayfaya erişim yetkiniz yok!")
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        role = request.form.get('role', 'user')  # default user
        can_add_product = bool(request.form.get('can_add_product'))

        if not username or not password:
            flash("Kullanıcı adı ve şifre zorunludur.")
            return redirect(url_for('add_user'))

        if User.query.filter_by(username=username).first():
            flash("Bu kullanıcı adı zaten var.")
            return redirect(url_for('add_user'))

        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password, role=role, can_add_product=can_add_product)
        db.session.add(new_user)
        db.session.commit()

        flash(f"{username} başarıyla eklendi.")
        return redirect(url_for('manage_users'))

    return render_template('admin/add_user.html')

@app.route('/admin/users/delete/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        flash("Bu işlemi yapmak için yetkiniz yok!")
        return redirect(url_for('index'))

    user = User.query.get_or_404(user_id)

    if user.id == current_user.id:
        flash("Kendi hesabınızı silemezsiniz!")
        return redirect(url_for('manage_users'))

    db.session.delete(user)
    db.session.commit()
    flash(f"{user.username} silindi.")
    return redirect(url_for('manage_users'))

@app.route('/admin/users/toggle_role/<int:user_id>', methods=['POST'])
@login_required
def toggle_user_role(user_id):
    if not current_user.is_admin:
        flash("Bu işlemi yapmak için yetkiniz yok!")
        return redirect(url_for('index'))

    user = User.query.get_or_404(user_id)

    if user.id == current_user.id:
        flash("Kendi rolünüzü değiştiremezsiniz!")
        return redirect(url_for('manage_users'))

    user.role = 'admin' if user.role == 'user' else 'user'
    db.session.commit()
    flash(f"{user.username} rolü güncellendi.")
    return redirect(url_for('manage_users'))


@app.route('/component/<int:comp_id>')
@login_required
def component_detail(comp_id):
    component = Component.query.get_or_404(comp_id)

    logs = BorrowLog.query.filter_by(comp_id=comp_id).order_by(BorrowLog.timestamp).all()

    borrow_history = []

    open_borrows = []

    for log in logs:
        if log.action == 'borrow':
            open_borrows.append({
                'user_id': log.user_id,
                'user_name': log.user.username if log.user else 'Bilinmiyor',
                'borrow_date': log.timestamp,
                'amount': log.amount,
                'return_date': None
            })
        elif log.action == 'return':
            amount_to_return = log.amount
            for borrow in open_borrows:
                if borrow['user_id'] == log.user_id and borrow['return_date'] is None:
                    if amount_to_return >= borrow['amount']:
                        borrow['return_date'] = log.timestamp
                        amount_to_return -= borrow['amount']
                    else:
                        # Split into two records
                        remaining = borrow['amount'] - amount_to_return
                        borrow['amount'] = amount_to_return
                        borrow['return_date'] = log.timestamp
                        open_borrows.append({
                            'user_id': borrow['user_id'],
                            'user_name': borrow['user_name'],
                            'borrow_date': borrow['borrow_date'],
                            'amount': remaining,
                            'return_date': None
                        })
                        amount_to_return = 0
                    if amount_to_return == 0:
                        break

    borrow_history = sorted(open_borrows, key=lambda x: x['borrow_date'], reverse=True)

    consume_logs = BorrowLog.query.filter_by(comp_id=comp_id, action='consume').order_by(BorrowLog.timestamp.desc()).all()
    consume_history = [{
        'user_name': rec.user.username if rec.user else 'Bilinmiyor',
        'timestamp': rec.timestamp,
        'amount': rec.amount,
    } for rec in consume_logs]

    return render_template('component_detail.html',
                           component=component,
                           borrow_history=borrow_history,
                           consume_history=consume_history)

@app.route('/components')
@login_required
def component_list():
    components = Component.query.all()
    return render_template('components/list.html', components=components)

def generate_component_code(type_, name, part_number):
    # Türün ilk 2 harfi büyük
    type_short = (type_ or "GE")[:2].upper()

    # Ortadaki kısım: part_number varsa onu kullan, yoksa isimden üret
    if part_number:
        middle = part_number.upper()
    else:
        parts = name.split()
        if not parts:
            middle = ""
        else:
            middle = parts[0][0].upper()
            for part in parts[1:]:
                match = re.search(r'\d+', part)
                if match:
                    middle += match.group()
                else:
                    middle += part[0].upper()

    # Aynı türden kaç tane var +1
    count = Component.query.filter_by(type=type_).count() + 1

    return f"{type_short}-{middle}-{count}"

@app.route('/add', methods=['GET', 'POST'])
@login_required
def add_component():
    if not current_user.has_add_permission():
      return "Bu işlemi yapmaya yetkiniz yok.", 403

    types = [t[0] for t in db.session.query(Component.type).distinct().all() if t[0]]
    existing_tags = Tag.query.order_by(Tag.name).all()

    selected_tags = []

    category = request.form.get('category')

    if request.method == 'POST':
        name = request.form['name'].strip()
        type_ = request.form.get('type', '').strip()

        if type_ == '__add_new__':
            new_type = request.form.get('new_type', '').strip()
            if not new_type:
                flash("Yeni tür boş bırakılamaz.")
                return render_template('add.html', types=types, existing_tags=existing_tags, selected_tags=selected_tags)
            type_ = new_type

        location = request.form.get('location', '').strip()
        description = request.form.get('description', '').strip()
        quantity = request.form['quantity'].strip()
        part_number = request.form.get('part_number', '').strip()

        tags_raw = request.form.getlist('tags[]')  # burada tüm seçilen ve yeni tagler var

        if not quantity.isdigit() or int(quantity) < 0:
            flash("Geçerli pozitif bir miktar giriniz.")
            return render_template('add.html', types=types, existing_tags=existing_tags, selected_tags=selected_tags)

        # Fotoğraf işleme
        photo = request.files.get('photo')
        if photo and photo.filename != '':
            filename = secure_filename(photo.filename)
            photo.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            image_url = url_for('static', filename='uploads/' + filename)
        else:
            image_url = "https://via.placeholder.com/300x200?text=Ürün"

        code = generate_component_code(type_, name, part_number)

        component = Component(
            name=name,
            category=category,
            type=type_,
            location=location,
            description=description,
            quantity=int(quantity),
            image_url=image_url,
            part_number=part_number,
            code=code
        )

        # Yeni tagları veritabanına ekle ve id listesini oluştur
        tag_ids = []
        for tag_item in tags_raw:
            if tag_item.startswith('new_'):
                tag_name = tag_item[4:].replace('-', ' ').strip()
                if not tag_name:
                    continue
                existing_tag = Tag.query.filter(func.lower(Tag.name) == tag_name.lower()).first()
                if existing_tag:
                    tag_ids.append(existing_tag.id)
                else:
                    new_tag = Tag(name=tag_name)
                    db.session.add(new_tag)
                    db.session.flush()  # id'yi hemen almak için
                    tag_ids.append(new_tag.id)
            else:
                # Var olan tag id'si
                if tag_item.isdigit():
                    tag_ids.append(int(tag_item))

        # Tüm tagleri ilişkilendir
        if tag_ids:
            tags = Tag.query.filter(Tag.id.in_(tag_ids)).all()
            component.tags.extend(tags)

        db.session.add(component)
        db.session.commit()

        flash(f"{name} bileşeni eklendi. Kod: {code}")
        return redirect(url_for('index'))

    # GET ise boş liste gönder
    return render_template('add.html', types=types, existing_tags=existing_tags, selected_tags=selected_tags)


@app.route('/delete/<int:comp_id>', methods=['POST'])
@login_required
def delete_component(comp_id):
    if current_user.role != 'admin':
        return "Bu işlemi yapmaya yetkiniz yok.", 403

    component = Component.query.get_or_404(comp_id)
    db.session.delete(component)
    db.session.commit()
    flash(f"{component.name} bileşeni silindi.")
    return redirect(url_for('index'))

@app.route('/consume/<int:comp_id>', methods=['POST'])
@login_required
def consume_component(comp_id):
    component = Component.query.get_or_404(comp_id)

    try:
        amount = int(request.form.get('amount', 1))
    except ValueError:
        flash("Geçersiz miktar.")
        return redirect(url_for('index'))

    if amount <= 0:
        flash("Miktar pozitif olmalıdır.")
        return redirect(url_for('index'))

    if component.quantity < amount:
        flash("Yeterli stok yok!", "danger")
        return redirect(url_for("index"))

    component.quantity -= amount
    log = BorrowLog(user_id=current_user.id, comp_id=component.id, action="consume", amount=amount)
    db.session.add(log)
    db.session.commit()
    flash(f"{component.name} ürününden {amount} adet sarf edildi.", "success")
    return redirect(url_for("index"))

@app.route('/component/<int:comp_id>/update_stock', methods=['POST'])
@login_required
def update_stock(comp_id):
    if current_user.role != 'admin':
        return "Bu işlemi yapmaya yetkiniz yok.", 403
    
    component = Component.query.get_or_404(comp_id)
    action = request.form.get('action')
    try:
        amount = int(request.form.get('amount', 0))
    except ValueError:
        flash("Geçersiz miktar.")
        return redirect(url_for('component_detail', comp_id=comp_id))
    
    if amount <= 0:
        flash("Miktar pozitif olmalıdır.")
        return redirect(url_for('component_detail', comp_id=comp_id))

    if action == 'increase':
        component.quantity += amount
        flash(f"{amount} adet stok eklendi.", "success")
    elif action == 'decrease':
        if component.quantity < amount:
            flash("Yeterli stok yok!", "danger")
            return redirect(url_for('component_detail', comp_id=comp_id))
        component.quantity -= amount
        flash(f"{amount} adet stok azaltıldı.", "success")
    else:
        flash("Geçersiz işlem.")
        return redirect(url_for('component_detail', comp_id=comp_id))

    db.session.commit()
    return redirect(url_for('component_detail', comp_id=comp_id))

@app.route('/azalan_stok')
@login_required
def low_stock():
    low_components = Component.query.filter(Component.quantity < 10).all()
    return render_template('low_stock.html', components=low_components)

@app.route('/borrow/<int:comp_id>', methods=['POST'])
@login_required
def borrow(comp_id):
    try:
        amount = int(request.form.get('amount', 1))
    except ValueError:
        flash("Geçersiz miktar.")
        return redirect(url_for('index'))

    location = request.form.get('location', '').strip()  # Yeni alanı alıyoruz

    component = Component.query.get_or_404(comp_id)

    if amount <= 0:
        flash("Miktar pozitif olmalıdır.")
        return redirect(url_for('index'))

    if component.quantity < amount:
        flash("Yeterli stok yok!")
        return redirect(url_for('index'))

    component.quantity -= amount

    log = BorrowLog(
        user_id=current_user.id,
        comp_id=comp_id,
        action='borrow',
        amount=amount,
        location=location  # Burada kaydediyoruz
    )
    db.session.add(log)
    db.session.commit()

    flash(f"{amount} adet {component.name} ödünç alındı.")
    return redirect(url_for('index'))


@app.route('/return/<int:comp_id>', methods=['GET', 'POST'])
@login_required
def return_component(comp_id):
    component = Component.query.get_or_404(comp_id)
    
    if request.method == 'POST':
        try:
            amount = int(request.form.get('amount', 1))
        except ValueError:
            flash("Geçersiz miktar.")
            return redirect(url_for('return_component', comp_id=comp_id))

        borrowed_amount = db.session.query(func.sum(BorrowLog.amount)).filter_by(
            user_id=current_user.id, comp_id=comp_id, action='borrow').scalar() or 0
        returned_amount = db.session.query(func.sum(BorrowLog.amount)).filter_by(
            user_id=current_user.id, comp_id=comp_id, action='return').scalar() or 0
        current_borrowed = borrowed_amount - returned_amount

        if current_borrowed < amount:
            flash("Bu kadar iade edemezsiniz.")
            return redirect(url_for('return_component', comp_id=comp_id))

        component.quantity += amount
        log = BorrowLog(user_id=current_user.id, comp_id=comp_id, action='return', amount=amount)
        db.session.add(log)
        db.session.commit()

        flash(f"{amount} adet {component.name} iade edildi.")
        return redirect(url_for('index'))
    
    return render_template('return.html', component=component)

@app.route('/my_borrowed')
@login_required
def my_borrowed():
    borrowed_subq = db.session.query(
        BorrowLog.comp_id,
        func.sum(BorrowLog.amount).label('borrowed_amount')
    ).filter_by(user_id=current_user.id, action='borrow').group_by(BorrowLog.comp_id).subquery()

    returned_subq = db.session.query(
        BorrowLog.comp_id,
        func.sum(BorrowLog.amount).label('returned_amount')
    ).filter_by(user_id=current_user.id, action='return').group_by(BorrowLog.comp_id).subquery()

    results = db.session.query(
        Component,
        (func.coalesce(borrowed_subq.c.borrowed_amount, 0) - func.coalesce(returned_subq.c.returned_amount, 0)).label('current_borrowed')
    ).join(borrowed_subq, Component.id == borrowed_subq.c.comp_id).outerjoin(returned_subq, Component.id == returned_subq.c.comp_id).filter(
        (func.coalesce(borrowed_subq.c.borrowed_amount, 0) - func.coalesce(returned_subq.c.returned_amount, 0)) > 0
    ).all()

    return render_template('my_borrowed.html', borrowed_items=results)

@app.route('/projelerim')
@login_required
def my_projects():
    projects = Project.query.filter_by(user_id=current_user.id).all()
    return render_template('projects.html', projects=projects)

@app.route('/istekler', methods=['GET', 'POST'])
@login_required
def requests():
    if request.method == 'POST':
        name = request.form['name'].strip()
        description = request.form.get('description', '').strip()
        if not name:
            flash("Ürün adı zorunlu.", "danger")
        else:
            req = Request(name=name, description=description, created_by=current_user.id)
            db.session.add(req)
            db.session.commit()
            flash("İstek eklendi.", "success")
        return redirect(url_for('requests'))
    requests = Request.query.order_by(Request.created_at.desc()).all()
    return render_template('requests.html', requests=requests)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        
        # Admin kullanıcısı oluşturma
        admin = User.query.filter_by(username="admin").first()
        if not admin:
            user = User(username="admin", role="admin")
            user.set_password("123")
            db.session.add(user)
            db.session.commit()

    app.run(host='0.0.0.0', port=5000, debug=True)


