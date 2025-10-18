from flask import Flask, render_template, request, redirect, url_for, session, flash
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import os
from werkzeug.utils import secure_filename
import uuid
import secrets 
from datetime import datetime, timedelta, date

# Configurações
app = Flask(__name__)
app.secret_key = 'sua_chave_secreta_aqui'
app.config['UPLOAD_FOLDER'] = 'static/img/products'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': '',
    'database': 'cafe_gourmet_db'
}

# --- FUNÇÕES AUXILIARES E DECORATOR ---
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'loggedin' not in session or not session.get('is_admin'):
            flash('Acesso negado. Você precisa ser um administrador.', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# --- ROTAS PÚBLICAS E DE CLIENTES ---
@app.route('/')
def index():
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM categories ORDER BY name")
        all_categories = cursor.fetchall()
        base_query = "SELECT * FROM products p WHERE 1=1"
        params = []
        selected_categories = request.args.getlist('category')
        if selected_categories:
            placeholders = ','.join(['%s'] * len(selected_categories))
            base_query += f" AND p.category_id IN ({placeholders})"
            params.extend(selected_categories)
        cursor.execute(base_query, tuple(params))
        products = cursor.fetchall()
        cursor.close()
        conn.close()
        return render_template('index.html', products=products, all_categories=all_categories)
    except Exception as e:
        return f"Erro ao conectar ao banco: {e}"
@app.route('/product/<int:product_id>')
def product(product_id):
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM products WHERE id = %s", (product_id,))
        product_data = cursor.fetchone()
        if not product_data:
            flash('Produto não encontrado!', 'danger')
            return redirect(url_for('index'))
        cursor.execute("SELECT r.rating, r.comment, r.created_at, u.name FROM reviews r JOIN users u ON r.user_id = u.id WHERE r.product_id = %s ORDER BY r.created_at DESC", (product_id,))
        reviews = cursor.fetchall()
        avg_rating = 0
        if reviews:
            avg_rating = sum(r['rating'] for r in reviews) / len(reviews)
        cursor.close()
        conn.close()
        return render_template('product_detail.html', product=product_data, reviews=reviews, avg_rating=avg_rating)
    except Exception as e:
        flash(f"Ocorreu um erro: {e}", 'danger')
        return redirect(url_for('index'))
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()
        if user and check_password_hash(user['password_hash'], password):
            session['loggedin'] = True
            session['id'] = user['id']
            session['name'] = user['name']
            session['is_admin'] = user.get('is_admin', False)
            return redirect(url_for('index'))
        else:
            flash('Email ou senha incorretos. Tente novamente.', 'danger')
    return render_template('login.html')
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        cpf = request.form['cpf']
        email = request.form['email']
        password = request.form['password']
        hashed_password = generate_password_hash(password)
        try:
            conn = mysql.connector.connect(**db_config)
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (name, cpf, email, password_hash) VALUES (%s, %s, %s, %s)",
                           (name, cpf, email, hashed_password))
            conn.commit()
            cursor.close()
            conn.close()
            flash('Cadastro realizado com sucesso! Faça o login.', 'success')
            return redirect(url_for('login'))
        except mysql.connector.Error as err:
            flash(f'Erro ao cadastrar: {err}', 'danger')
            return redirect(url_for('register'))
    return render_template('register.html')
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        if user:
            token = secrets.token_urlsafe(20)
            expires_at = datetime.now() + timedelta(hours=1)
            cursor.execute("INSERT INTO password_resets (user_id, token, expires_at) VALUES (%s, %s, %s)",
                           (user['id'], token, expires_at))
            conn.commit()
            reset_link = url_for('reset_password', token=token, _external=True)
            print("--- SIMULAÇÃO DE E-MAIL ---")
            print(f"Para: {email}")
            print(f"Clique no link para resetar sua senha (válido por 1 hora): {reset_link}")
            print("---------------------------")
        cursor.close()
        conn.close()
        flash('Se o e-mail estiver cadastrado, um link de recuperação foi enviado (verifique o console).', 'info')
        return redirect(url_for('login'))
    return render_template('forgot_password.html')
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM password_resets WHERE token = %s AND expires_at > NOW()", (token,))
    reset_request = cursor.fetchone()
    if not reset_request:
        cursor.close()
        conn.close()
        flash('Link de recuperação inválido ou expirado.', 'danger')
        return redirect(url_for('forgot_password'))
    if request.method == 'POST':
        password = request.form.get('password')
        hashed_password = generate_password_hash(password)
        cursor.execute("UPDATE users SET password_hash = %s WHERE id = %s", (hashed_password, reset_request['user_id']))
        cursor.execute("DELETE FROM password_resets WHERE id = %s", (reset_request['id'],))
        conn.commit()
        cursor.close()
        conn.close()
        flash('Sua senha foi atualizada com sucesso! Você já pode fazer o login.', 'success')
        return redirect(url_for('login'))
    cursor.close()
    conn.close()
    return render_template('reset_password.html', token=token)

# --- ROTAS DE ASSINATURA ---
@app.route('/subscriptions')
def subscriptions_page():
    return render_template('subscriptions.html')

@app.route('/subscribe', methods=['POST'])
def subscribe():
    if 'loggedin' not in session:
        flash('Você precisa estar logado para assinar um plano.', 'warning')
        return redirect(url_for('login'))

    user_id = session['id']
    plan_name = request.form.get('plan_name')
    plan_price = request.form.get('plan_price')

    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor(dictionary=True)

    # Verifica se o usuário já tem uma assinatura ativa
    cursor.execute("SELECT * FROM subscriptions WHERE user_id = %s AND status = 'ativa'", (user_id,))
    existing_subscription = cursor.fetchone()

    if existing_subscription:
        flash('Você já possui uma assinatura ativa.', 'info')
        return redirect(url_for('my_account'))

    # Calcula a data da próxima cobrança (daqui a 30 dias)
    next_billing = date.today() + timedelta(days=30)
    
    # Insere a nova assinatura
    cursor.execute("INSERT INTO subscriptions (user_id, plan_name, plan_price, next_billing_date) VALUES (%s, %s, %s, %s)",
                   (user_id, plan_name, plan_price, next_billing))
    conn.commit()
    cursor.close()
    conn.close()

    flash(f'Obrigado por assinar o plano {plan_name}! Sua assinatura já está ativa.', 'success')
    return redirect(url_for('my_account'))

@app.route('/cancel_subscription', methods=['POST'])
def cancel_subscription():
    if 'loggedin' not in session:
        return redirect(url_for('login'))

    user_id = session['id']
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor()
    # Atualiza o status da assinatura para 'cancelada'
    cursor.execute("UPDATE subscriptions SET status = 'cancelada' WHERE user_id = %s AND status = 'ativa'", (user_id,))
    conn.commit()
    cursor.close()
    conn.close()

    flash('Sua assinatura foi cancelada com sucesso.', 'info')
    return redirect(url_for('my_account'))


# --- 'my_account'---
@app.route('/my_account', methods=['GET', 'POST'])
def my_account():
    if 'loggedin' not in session: return redirect(url_for('login'))
    user_id = session['id']
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor(dictionary=True)
    if request.method == 'POST':
        street = request.form['street']; number = request.form['number']; complement = request.form.get('complement', ''); neighborhood = request.form['neighborhood']; city = request.form['city']; state = request.form['state']; zip_code = request.form['zip_code']
        cursor.execute("INSERT INTO addresses (user_id, street, number, complement, neighborhood, city, state, zip_code) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)", (user_id, street, number, complement, neighborhood, city, state, zip_code)); conn.commit()
        flash('Endereço adicionado com sucesso!', 'success'); return redirect(url_for('my_account'))
    
    cursor.execute("SELECT * FROM addresses WHERE user_id = %s", (user_id,))
    addresses = cursor.fetchall()
    
    cursor.execute("SELECT id, order_date, total_amount, status FROM orders WHERE user_id = %s ORDER BY order_date DESC", (user_id,))
    orders = cursor.fetchall()
    for order in orders:
        cursor.execute("SELECT p.name, p.id as product_id, oi.quantity FROM order_items oi JOIN products p ON oi.product_id = p.id WHERE oi.order_id = %s", (order['id'],)); order['products'] = cursor.fetchall()

    # Busca a assinatura do usuário
    cursor.execute("SELECT * FROM subscriptions WHERE user_id = %s", (user_id,))
    subscription = cursor.fetchone()

    cursor.close()
    conn.close()
    return render_template('my_account.html', addresses=addresses, orders=orders, subscription=subscription)

@app.route('/add_to_cart/<int:product_id>', methods=['POST'])
def add_to_cart(product_id):
    if 'loggedin' not in session: flash('Você precisa estar logado para adicionar itens ao carrinho!', 'warning'); return redirect(url_for('login'))
    try:
        cart = session.get('cart', {}); quantity = int(request.form.get('quantity', 1))
        conn = mysql.connector.connect(**db_config); cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT name, price, stock_quantity FROM products WHERE id = %s", (product_id,)); product = cursor.fetchone(); cursor.close(); conn.close()
        if not product: flash('Produto não encontrado!', 'danger'); return redirect(url_for('index'))
        product_id_str = str(product_id)
        if product_id_str in cart:
            if cart[product_id_str]['quantity'] + quantity > product['stock_quantity']: flash(f'Estoque insuficiente para {product["name"]}.', 'warning')
            else: cart[product_id_str]['quantity'] += quantity; flash(f'{product["name"]} teve a quantidade atualizada no carrinho!', 'success')
        else:
            if quantity > product['stock_quantity']: flash(f'Estoque insuficiente para {product["name"]}.', 'warning')
            else: cart[product_id_str] = { 'name': product['name'], 'price': float(product['price']), 'quantity': quantity }; flash(f'{product["name"]} adicionado ao carrinho!', 'success')
        session['cart'] = cart; session.modified = True
    except Exception as e: flash(f'Ocorreu um erro: {e}', 'danger')
    return redirect(request.referrer or url_for('index'))
@app.route('/cart')
def cart():
    if 'loggedin' not in session: flash('Faça login para ver seu carrinho.', 'warning'); return redirect(url_for('login'))
    cart_items = session.get('cart', {}); total_price = sum(item['price'] * item['quantity'] for item in cart_items.values())
    return render_template('cart.html', cart_items=cart_items, total_price=total_price)
@app.route('/checkout')
def checkout():
    if 'loggedin' not in session: flash('Por favor, faça login para finalizar a compra.', 'info'); return redirect(url_for('login'))
    cart = session.get('cart', {})
    if not cart: flash('Seu carrinho está vazio!', 'warning'); return redirect(url_for('cart'))
    total_price = sum(item['price'] * item['quantity'] for item in cart.values()); user_id = session['id']
    conn = mysql.connector.connect(**db_config); cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM addresses WHERE user_id = %s", (user_id,)); addresses = cursor.fetchall(); cursor.close(); conn.close()
    return render_template('checkout.html', cart_items=cart, total_price=total_price, addresses=addresses)
@app.route('/place_order', methods=['POST'])
def place_order():
    if 'loggedin' not in session or not session.get('cart'): return redirect(url_for('index'))
    user_id = session['id']; cart = session['cart']; total_price = sum(item['price'] * item['quantity'] for item in cart.values())
    address_id = request.form.get('address_id'); payment_method = request.form.get('payment_method')
    if not address_id or not payment_method: flash('Por favor, selecione um endereço e uma forma de pagamento.', 'danger'); return redirect(url_for('checkout'))
    try:
        conn = mysql.connector.connect(**db_config); cursor = conn.cursor()
        cursor.execute("INSERT INTO orders (user_id, shipping_address_id, total_amount, status) VALUES (%s, %s, %s, %s)", (user_id, address_id, total_price, 'aguardando_pagamento')); order_id = cursor.lastrowid
        for product_id, item in cart.items():
            cursor.execute("INSERT INTO order_items (order_id, product_id, quantity, unit_price) VALUES (%s, %s, %s, %s)", (order_id, int(product_id), item['quantity'], item['price']))
            cursor.execute("UPDATE products SET stock_quantity = stock_quantity - %s WHERE id = %s", (item['quantity'], int(product_id)))
        conn.commit(); cursor.close(); conn.close(); session.pop('cart', None); session.modified = True
        return redirect(url_for('order_confirmation', order_id=order_id))
    except Exception as e: flash(f"Ocorreu um erro ao processar seu pedido: {e}", 'danger'); return redirect(url_for('checkout'))
@app.route('/order_confirmation/<int:order_id>')
def order_confirmation(order_id):
    if 'loggedin' not in session: return redirect(url_for('login'))
    return render_template('order_confirmation.html', order_id=order_id)
@app.route('/update_cart/<int:product_id>', methods=['POST'])
def update_cart(product_id):
    if 'loggedin' not in session or 'cart' not in session: return redirect(url_for('login'))
    try:
        new_quantity = int(request.form['quantity']); product_id_str = str(product_id); cart = session['cart']
        if product_id_str in cart:
            if new_quantity > 0:
                conn = mysql.connector.connect(**db_config); cursor = conn.cursor(dictionary=True)
                cursor.execute("SELECT stock_quantity, name FROM products WHERE id = %s", (product_id,)); product = cursor.fetchone(); cursor.close(); conn.close()
                if new_quantity > product['stock_quantity']: flash(f"Estoque insuficiente para {product['name']}. Disponível: {product['stock_quantity']}", 'warning')
                else: cart[product_id_str]['quantity'] = new_quantity; flash('Carrinho atualizado!', 'success')
            else: cart.pop(product_id_str); flash('Item removido do carrinho.', 'success')
        session['cart'] = cart; session.modified = True
    except Exception as e: flash(f'Ocorreu um erro ao atualizar o carrinho: {e}', 'danger')
    return redirect(url_for('cart'))
@app.route('/remove_from_cart/<int:product_id>', methods=['POST'])
def remove_from_cart(product_id):
    if 'loggedin' not in session or 'cart' not in session: return redirect(url_for('login'))
    product_id_str = str(product_id); cart = session['cart']
    if product_id_str in cart: cart.pop(product_id_str); flash('Item removido do carrinho.', 'success')
    session['cart'] = cart; session.modified = True
    return redirect(url_for('cart'))
@app.route('/clear_cart', methods=['POST'])
def clear_cart():
    if 'loggedin' not in session: return redirect(url_for('login'))
    session.pop('cart', None); session.modified = True; flash('Seu carrinho foi esvaziado.', 'success')
    return redirect(url_for('cart'))
@app.route('/review/<int:order_id>/<int:product_id>', methods=['GET', 'POST'])
def review(order_id, product_id):
    if 'loggedin' not in session: return redirect(url_for('login'))
    user_id = session['id']; conn = mysql.connector.connect(**db_config); cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT id FROM reviews WHERE user_id = %s AND product_id = %s AND order_id = %s", (user_id, product_id, order_id)); existing_review = cursor.fetchone()
    if existing_review: flash('Você já avaliou este produto para este pedido.', 'info'); return redirect(url_for('my_account'))
    if request.method == 'POST':
        rating = request.form.get('rating'); comment = request.form.get('comment', '')
        if not rating: flash('Por favor, selecione uma nota.', 'danger'); return redirect(url_for('review', order_id=order_id, product_id=product_id))
        cursor.execute("INSERT INTO reviews (user_id, product_id, order_id, rating, comment) VALUES (%s, %s, %s, %s, %s)", (user_id, product_id, order_id, rating, comment)); conn.commit(); cursor.close(); conn.close()
        flash('Obrigado pela sua avaliação!', 'success'); return redirect(url_for('my_account'))
    cursor.execute("SELECT name FROM products WHERE id = %s", (product_id,)); product = cursor.fetchone(); cursor.close(); conn.close()
    if not product: return 'Produto não encontrado', 404
    return render_template('review.html', product=product, order_id=order_id, product_id=product_id)
@app.route('/admin/dashboard')
@admin_required
def admin_dashboard(): return render_template('admin/dashboard.html')
@app.route('/admin/products')
@admin_required
def admin_products():
    conn = mysql.connector.connect(**db_config); cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT p.*, c.name as category_name FROM products p JOIN categories c ON p.category_id = c.id ORDER BY p.id ASC"); products = cursor.fetchall(); cursor.close(); conn.close()
    return render_template('admin/products_list.html', products=products)
@app.route('/admin/products/add', methods=['GET', 'POST'])
@admin_required
def add_product():
    if request.method == 'POST':
        name = request.form['name']; description = request.form['description']; price = request.form['price']; stock_quantity = request.form['stock_quantity']; category_id = request.form['category_id']; image_url = ''
        if 'image' in request.files:
            image_file = request.files['image']
            if image_file and allowed_file(image_file.filename):
                filename = secure_filename(image_file.filename); unique_filename = str(uuid.uuid4()) + "_" + filename; image_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename); image_file.save(image_path); image_url = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename).replace('\\', '/')
        conn = mysql.connector.connect(**db_config); cursor = conn.cursor()
        cursor.execute("INSERT INTO products (name, description, price, stock_quantity, category_id, image_url) VALUES (%s, %s, %s, %s, %s, %s)", (name, description, price, stock_quantity, category_id, image_url)); conn.commit(); cursor.close(); conn.close()
        flash('Produto adicionado com sucesso!', 'success'); return redirect(url_for('admin_products'))
    conn = mysql.connector.connect(**db_config); cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM categories"); categories = cursor.fetchall(); cursor.close(); conn.close()
    return render_template('admin/product_form.html', categories=categories, title="Adicionar Novo Produto", product=None)
@app.route('/admin/products/edit/<int:product_id>', methods=['GET', 'POST'])
@admin_required
def edit_product(product_id):
    conn = mysql.connector.connect(**db_config); cursor = conn.cursor(dictionary=True)
    if request.method == 'POST':
        name = request.form['name']; description = request.form['description']; price = request.form['price']; stock_quantity = request.form['stock_quantity']; category_id = request.form['category_id']
        cursor.execute("SELECT image_url FROM products WHERE id = %s", (product_id,)); image_url = cursor.fetchone()['image_url']
        if 'image' in request.files:
            image_file = request.files['image']
            if image_file and allowed_file(image_file.filename):
                filename = secure_filename(image_file.filename); unique_filename = str(uuid.uuid4()) + "_" + filename; image_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename); image_file.save(image_path); image_url = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename).replace('\\', '/')
        cursor.execute("UPDATE products SET name=%s, description=%s, price=%s, stock_quantity=%s, category_id=%s, image_url=%s WHERE id=%s", (name, description, price, stock_quantity, category_id, image_url, product_id)); conn.commit(); cursor.close(); conn.close()
        flash('Produto atualizado com sucesso!', 'success'); return redirect(url_for('admin_products'))
    cursor.execute("SELECT * FROM products WHERE id = %s", (product_id,)); product = cursor.fetchone()
    cursor.execute("SELECT * FROM categories"); categories = cursor.fetchall(); cursor.close(); conn.close()
    if not product: flash('Produto não encontrado.', 'danger'); return redirect(url_for('admin_products'))
    return render_template('admin/product_form.html', categories=categories, title="Editar Produto", product=product)
@app.route('/admin/products/delete/<int:product_id>', methods=['POST'])
@admin_required
def delete_product(product_id):
    try:
        conn = mysql.connector.connect(**db_config); cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT image_url FROM products WHERE id = %s", (product_id,)); product = cursor.fetchone()
        if product and product['image_url']:
            image_path = product['image_url'].lstrip('/');
            if os.path.exists(image_path): os.remove(image_path)
        cursor.execute("DELETE FROM products WHERE id = %s", (product_id,)); conn.commit(); cursor.close(); conn.close()
        flash('Produto excluído com sucesso!', 'success')
    except Exception as e: flash(f'Erro ao excluir o produto: {e}', 'danger')
    return redirect(url_for('admin_products'))
@app.route('/admin/orders')
@admin_required
def admin_orders():
    conn = mysql.connector.connect(**db_config); cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT o.*, u.name as customer_name FROM orders o JOIN users u ON o.user_id = u.id ORDER BY o.order_date DESC"); orders = cursor.fetchall(); cursor.close(); conn.close()
    order_statuses = ['aguardando_pagamento', 'em_preparacao', 'em_rota', 'entregue', 'cancelado']
    return render_template('admin/orders_list.html', orders=orders, statuses=order_statuses)
@app.route('/admin/orders/update_status/<int:order_id>', methods=['POST'])
@admin_required
def update_order_status(order_id):
    new_status = request.form.get('status')
    if new_status:
        try:
            conn = mysql.connector.connect(**db_config); cursor = conn.cursor()
            cursor.execute("UPDATE orders SET status = %s WHERE id = %s", (new_status, order_id)); conn.commit(); cursor.close(); conn.close()
            flash(f'Status do pedido #{order_id} atualizado com sucesso!', 'success')
        except Exception as e: flash(f'Erro ao atualizar o status: {e}', 'danger')
    return redirect(url_for('admin_orders'))
@app.route('/admin/reports/sales')
@admin_required
def report_sales():
    conn = mysql.connector.connect(**db_config); cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT o.id, o.order_date, u.name as customer_name, o.total_amount FROM orders o JOIN users u ON o.user_id = u.id WHERE o.status = 'entregue' ORDER BY o.order_date DESC"); sales = cursor.fetchall(); cursor.close(); conn.close()
    return render_template('admin/report_sales.html', sales=sales)
@app.route('/admin/reports/low_stock')
@admin_required
def report_low_stock():
    conn = mysql.connector.connect(**db_config); cursor = conn.cursor(dictionary=True)
    stock_limit = 10
    cursor.execute("SELECT id, name, stock_quantity FROM products WHERE stock_quantity <= %s ORDER BY stock_quantity ASC", (stock_limit,)); low_stock_products = cursor.fetchall(); cursor.close(); conn.close()
    return render_template('admin/report_low_stock.html', products=low_stock_products, limit=stock_limit)
if __name__ == '__main__':
    app.run(debug=True)