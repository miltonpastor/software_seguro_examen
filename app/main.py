import secrets
from flask import Flask, request, g
from flask_restx import Api, Resource, fields # type: ignore
from functools import wraps
from .db import get_connection, init_db
from .custom_logger import write_custom_log
from .jwt_utils import *

# Define a simple in-memory token store
tokens = {}

## Custom logging replaces standard logging

# Configure Swagger security scheme for Bearer tokens
authorizations = {
    'Bearer': {
        'type': 'apiKey',
        'in': 'header',
        'name': 'Authorization',
        'description': "Enter your token in the format **Bearer <token>**"
    }
}

app = Flask(__name__)
api = Api(
    app,
    version='1.0',
    title='Core Bancario API',
    description='API para operaciones bancarias, incluyendo autenticación y operaciones de cuenta.',
    doc='/swagger',  # Swagger UI endpoint
    authorizations=authorizations,
    security='Bearer'
)

# Create namespaces for authentication and bank operations
auth_ns = api.namespace('auth', description='Operaciones de autenticación')
bank_ns = api.namespace('bank', description='Operaciones bancarias')

# Define the expected payload models for Swagger
login_model = auth_ns.model('Login', {
    'username': fields.String(required=True, description='Nombre de usuario', example='user1'),
    'password': fields.String(required=True, description='Contraseña', example='pass1')
})

deposit_model = bank_ns.model('Deposit', {
    'account_number': fields.Integer(required=True, description='Número de cuenta', example=123),
    'amount': fields.Float(required=True, description='Monto a depositar', example=100)
})

withdraw_model = bank_ns.model('Withdraw', {
    'amount': fields.Float(required=True, description='Monto a retirar', example=100)
})

transfer_model = bank_ns.model('Transfer', {
    'target_username': fields.String(required=True, description='Usuario destino', example='user2'),
    'amount': fields.Float(required=True, description='Monto a transferir', example=100)
})

credit_payment_model = bank_ns.model('CreditPayment', {
    'amount': fields.Float(required=True, description='Monto de la compra a crédito', example=100)
})

pay_credit_balance_model = bank_ns.model('PayCreditBalance', {
    'amount': fields.Float(required=True, description='Monto a abonar a la deuda de la tarjeta', example=50)
})

# ---------------- Authentication Endpoints ----------------

@auth_ns.route('/login')
class Login(Resource):
    @auth_ns.expect(login_model, validate=True)
    @auth_ns.doc('login')
    def post(self):
        print(f"Writing log SI ENTRA QUI ..............................")
        """Inicia sesión y devuelve un token JWT de autenticación."""
        data = api.payload
        nombre_usuario = data.get("username")
        contrasena = data.get("password")
        
        # Registrar intento de login (custom log)
        remote_ip = request.remote_addr or "-"
        write_custom_log(
            log_type="INFO",
            remote_ip=remote_ip,
            username=nombre_usuario,
            action="Intento de login",
            http_code=0
        )
        
        conexion = get_connection()
        cursor = conexion.cursor()
        cursor.execute("SELECT id, username, password, role, full_name, email FROM bank.users WHERE username = %s", (nombre_usuario,))
        usuario = cursor.fetchone()
        
        if usuario and usuario[2] == contrasena:
            # Creamos el arreglo de datos del usuario
            datos_usuario = {
                "id": usuario[0],
                "username": usuario[1],
                "role": usuario[3],
                "full_name": usuario[4],
                "email": usuario[5]
            }
            # Generamos el JWT usando la función actualizada
            token_jwt = generate_jwt_token(datos_usuario)
            # Guardamos el token en la base de datos para manejo de blacklist
            cursor.execute("INSERT INTO bank.tokens (token, user_id) VALUES (%s, %s)", (token_jwt, usuario[0]))
            conexion.commit()
            cursor.close()
            conexion.close()
            # Custom log: login exitoso
            write_custom_log(
                log_type="INFO",
                remote_ip=remote_ip,
                username=nombre_usuario,
                action="Login exitoso",
                http_code=200
            )
            return {"message": "Login successful", "token": token_jwt}, 200
        else:
            cursor.close()
            conexion.close()
            # Custom log: credenciales inválidas
            write_custom_log(
                log_type="WARNING",
                remote_ip=remote_ip,
                username=nombre_usuario,
                action="Credenciales inválidas",
                http_code=401
            )
            api.abort(401, "Invalid credentials")

@auth_ns.route('/logout')
class Logout(Resource):
    @auth_ns.doc('logout')
    def post(self):
        """Invalida el token JWT añadiéndolo a la blacklist."""
        header_autorizacion = request.headers.get("Authorization", "")
        
        try:
            # Extraer token del header usando la función utilitaria
            token_jwt = extraer_token_de_header(header_autorizacion)
            
            # Validar el token antes de proceder
            es_valido, payload, mensaje_error = validar_token_jwt(token_jwt)
            
            if not es_valido:
                remote_ip = request.remote_addr or "-"
                username = payload.get('nombre_usuario', 'desconocido') if payload else "-"
                write_custom_log(
                    log_type="WARNING",
                    remote_ip=remote_ip,
                    username=username,
                    action=f"Intento de logout con token inválido: {mensaje_error}",
                    http_code=401
                )
                api.abort(401, mensaje_error)
            
            # Eliminar token de la base de datos (blacklist)
            conexion = get_connection()
            cursor = conexion.cursor()
            cursor.execute("DELETE FROM bank.tokens WHERE token = %s", (token_jwt,))
            
            if cursor.rowcount == 0:
                conexion.commit()
                cursor.close()
                conexion.close()
                remote_ip = request.remote_addr or "-"
                write_custom_log(
                    log_type="WARNING",
                    remote_ip=remote_ip,
                    username=username,
                    action="Intento de logout con token no encontrado en BD",
                    http_code=401
                )
                api.abort(401, "Token no encontrado")
            
            conexion.commit()
            cursor.close()
            conexion.close()
            
            write_custom_log(
                log_type="INFO",
                remote_ip=remote_ip,
                username=username,
                action="Logout exitoso",
                http_code=200
            )
            return {"message": "Logout successful"}, 200
            
        except ValueError as e:
            remote_ip = request.remote_addr or "-"
            write_custom_log(
                log_type="WARNING",
                remote_ip=remote_ip,
                username="-",
                action=f"Error en header de autorización: {str(e)}",
                http_code=401
            )
            api.abort(401, str(e))

# ---------------- Decorador Token-Required ----------------

def token_required(f):
    @wraps(f)
    def decorador(*args, **kwargs):
        header_autorizacion = request.headers.get("Authorization", "")
        
        try:
            # Extraer token del header
            token_jwt = extraer_token_de_header(header_autorizacion)
            remote_ip = request.remote_addr or "-"
            write_custom_log(
                log_type="DEBUG",
                remote_ip=remote_ip,
                username="-",
                action=f"Token recibido: {token_jwt[:20]}...",
                http_code=0
            )
            
            # Validar token JWT
            es_valido, payload, mensaje_error = validar_token_jwt(token_jwt)
            
            if not es_valido:
                write_custom_log(
                    log_type="WARNING",
                    remote_ip=remote_ip,
                    username="-",
                    action=f"Token inválido: {mensaje_error}",
                    http_code=401
                )
                api.abort(401, mensaje_error)
            
            # Verificar que el token esté en la base de datos (no en blacklist)
            conexion = get_connection()
            cursor = conexion.cursor()
            cursor.execute("SELECT COUNT(*) FROM bank.tokens WHERE token = %s", (token_jwt,))
            token_existe = cursor.fetchone()[0] > 0
            cursor.close()
            conexion.close()
            
            if not token_existe:
                write_custom_log(
                    log_type="WARNING",
                    remote_ip=remote_ip,
                    username="-",
                    action="Token no encontrado en BD o en blacklist",
                    http_code=401
                )
                api.abort(401, "Token ha sido invalidado")
            
            # Establecer información del usuario en g usando los datos del token
            g.usuario = {
                "id": payload['id_usuario'],
                "username": payload['nombre_usuario'],
                "role": payload['rol'],
                "full_name": payload.get('nombre_completo', ''),
                "email": payload.get('correo', '')
            }
            
            write_custom_log(
                log_type="DEBUG",
                remote_ip=remote_ip,
                username=g.usuario['username'],
                action="Usuario autenticado",
                http_code=0
            )
            return f(*args, **kwargs)
            
        except ValueError as e:
            write_custom_log(
                log_type="WARNING",
                remote_ip=request.remote_addr or "-",
                username="-",
                action=f"Error en header de autorización: {str(e)}",
                http_code=401
            )
            api.abort(401, str(e))
        except Exception as e:
            write_custom_log(
                log_type="ERROR",
                remote_ip=request.remote_addr or "-",
                username="-",
                action=f"Error en validación de token: {str(e)}",
                http_code=401
            )
            api.abort(401, "Error de validación de token")
    
    return decorador

@auth_ns.route('/verificar')
class VerificarToken(Resource):
    @auth_ns.doc('verificar_token')
    @token_required
    def get(self):
        """Verifica si el token JWT es válido y devuelve información del usuario."""
        return {
            "message": "Token es válido",
            "usuario": {
                "id": g.usuario['id'],
                "username": g.usuario['username'],
                "role": g.usuario['role'],
                "full_name": g.usuario['full_name'],
                "email": g.usuario['email']
            }
        }, 200

@auth_ns.route('/refrescar')
class RefrescarToken(Resource):
    @auth_ns.doc('refrescar_token')
    @token_required
    def post(self):
        """Genera un nuevo token JWT para el usuario autenticado."""
        try:
            # Obtener token actual
            header_autorizacion = request.headers.get("Authorization", "")
            token_actual = extraer_token_de_header(header_autorizacion)
            
            # Validar token actual
            es_valido, payload_actual, mensaje_error = validar_token_jwt(token_actual)
            
            if not es_valido:
                api.abort(401, mensaje_error)
            
            # Generar nuevo token usando la función utilitaria
            nuevo_token = generar_token_refresco(payload_actual)
            
            # Actualizar token en base de datos
            conexion = get_connection()
            cursor = conexion.cursor()
            cursor.execute("DELETE FROM bank.tokens WHERE token = %s", (token_actual,))
            cursor.execute("INSERT INTO bank.tokens (token, user_id) VALUES (%s, %s)", 
                         (nuevo_token, g.usuario['id']))
            conexion.commit()
            cursor.close()
            conexion.close()
            
            write_custom_log(
                log_type="INFO",
                remote_ip=request.remote_addr or "-",
                username=g.usuario['username'],
                action="Token refrescado",
                http_code=200
            )
            return {"message": "Token refrescado exitosamente", "token": nuevo_token}, 200
        except Exception as e:
            write_custom_log(
                log_type="ERROR",
                remote_ip=request.remote_addr or "-",
                username=g.usuario['username'] if hasattr(g, 'usuario') else "-",
                action=f"Error al refrescar token: {str(e)}",
                http_code=500
            )
            api.abort(500, "Error interno al refrescar token")

# ---------------- Banking Operation Endpoints ----------------

@bank_ns.route('/deposit')
class Deposit(Resource):
    @bank_ns.expect(deposit_model, validate=True)
    @bank_ns.doc('deposit')
    @token_required
    def post(self):
        """
        Realiza un depósito en la cuenta especificada.
        Se requiere el número de cuenta y el monto a depositar.
        """
        write_custom_log(
            log_type="INFO",
            remote_ip=request.remote_addr or "-",
            username=g.usuario['username'],
            action="Operación de depósito iniciada",
            http_code=0
        )
        
        datos = api.payload
        numero_cuenta = datos.get("account_number")
        monto = datos.get("amount", 0)
        
        if monto <= 0:
            write_custom_log(
                log_type="WARNING",
                remote_ip=request.remote_addr or "-",
                username=g.usuario['username'],
                action=f"Monto de depósito inválido: {monto}",
                http_code=400
            )
            api.abort(400, "El monto debe ser mayor que cero")
        
        conexion = get_connection()
        cursor = conexion.cursor()
        
        # Actualizar la cuenta especificada usando su número de cuenta (clave primaria)
        cursor.execute(
            "UPDATE bank.accounts SET balance = balance + %s WHERE id = %s RETURNING balance",
            (monto, numero_cuenta)
        )
        resultado = cursor.fetchone()
        
        if not resultado:
            conexion.rollback()
            cursor.close()
            conexion.close()
            write_custom_log(
                log_type="WARNING",
                remote_ip=request.remote_addr or "-",
                username=g.usuario['username'],
                action=f"Depósito fallido - Cuenta {numero_cuenta} no encontrada",
                http_code=404
            )
            api.abort(404, "Cuenta no encontrada")
        
        nuevo_balance = float(resultado[0])
        conexion.commit()
        cursor.close()
        conexion.close()
        
        write_custom_log(
            log_type="INFO",
            remote_ip=request.remote_addr or "-",
            username=g.usuario['username'],
            action=f"Depósito exitoso: ${monto} a cuenta {numero_cuenta}",
            http_code=200
        )
        return {"message": "Depósito exitoso", "new_balance": nuevo_balance}, 200

@bank_ns.route('/withdraw')
class Withdraw(Resource):
    @bank_ns.expect(withdraw_model, validate=True)
    @bank_ns.doc('withdraw')
    @token_required
    def post(self):
        """Realiza un retiro de la cuenta del usuario autenticado."""
        write_custom_log(
            log_type="INFO",
            remote_ip=request.remote_addr or "-",
            username=g.usuario['username'],
            action="Operación de retiro iniciada",
            http_code=0
        )
        
        datos = api.payload
        monto = datos.get("amount", 0)
        
        if monto <= 0:
            write_custom_log(
                log_type="WARNING",
                remote_ip=request.remote_addr or "-",
                username=g.usuario['username'],
                action=f"Monto de retiro inválido: {monto}",
                http_code=400
            )
            api.abort(400, "El monto debe ser mayor que cero")
        
        id_usuario = g.usuario['id']
        conexion = get_connection()
        cursor = conexion.cursor()
        
        cursor.execute("SELECT balance FROM bank.accounts WHERE user_id = %s", (id_usuario,))
        fila = cursor.fetchone()
        
        if not fila:
            cursor.close()
            conexion.close()
            write_custom_log(
                log_type="ERROR",
                remote_ip=request.remote_addr or "-",
                username=g.usuario['username'],
                action="Cuenta no encontrada para retiro",
                http_code=404
            )
            api.abort(404, "Cuenta no encontrada")
        
        balance_actual = float(fila[0])
        
        if balance_actual < monto:
            cursor.close()
            conexion.close()
            write_custom_log(
                log_type="WARNING",
                remote_ip=request.remote_addr or "-",
                username=g.usuario['username'],
                action=f"Fondos insuficientes para retiro: {monto} (balance: {balance_actual})",
                http_code=400
            )
            api.abort(400, "Fondos insuficientes")
        
        cursor.execute("UPDATE bank.accounts SET balance = balance - %s WHERE user_id = %s RETURNING balance", 
                      (monto, id_usuario))
        nuevo_balance = float(cursor.fetchone()[0])
        conexion.commit()
        cursor.close()
        conexion.close()
        
        write_custom_log(
            log_type="INFO",
            remote_ip=request.remote_addr or "-",
            username=g.usuario['username'],
            action=f"Retiro exitoso: ${monto}",
            http_code=200
        )
        return {"message": "Retiro exitoso", "new_balance": nuevo_balance}, 200

@bank_ns.route('/transfer')
class Transfer(Resource):
    @bank_ns.expect(transfer_model, validate=True)
    @bank_ns.doc('transfer')
    @token_required
    def post(self):
        """Transfiere fondos desde la cuenta del usuario autenticado a otra cuenta."""
        write_custom_log(
            log_type="INFO",
            remote_ip=request.remote_addr or "-",
            username=g.usuario['username'],
            action="Operación de transferencia iniciada",
            http_code=0
        )
        
        datos = api.payload
        usuario_destino = datos.get("target_username")
        monto = datos.get("amount", 0)
        
        if not usuario_destino or monto <= 0:
            write_custom_log(
                log_type="WARNING",
                remote_ip=request.remote_addr or "-",
                username=g.usuario['username'],
                action=f"Datos de transferencia inválidos - destino: {usuario_destino}, monto: {monto}",
                http_code=400
            )
            api.abort(400, "Datos inválidos")
        
        if usuario_destino == g.usuario['username']:
            write_custom_log(
                log_type="WARNING",
                remote_ip=request.remote_addr or "-",
                username=g.usuario['username'],
                action="Intento de auto-transferencia",
                http_code=400
            )
            api.abort(400, "No se puede transferir a la misma cuenta")
        
        conexion = get_connection()
        cursor = conexion.cursor()
        
        # Verificar balance del remitente
        cursor.execute("SELECT balance FROM bank.accounts WHERE user_id = %s", (g.usuario['id'],))
        fila = cursor.fetchone()
        
        if not fila:
            cursor.close()
            conexion.close()
            write_custom_log(
                log_type="ERROR",
                remote_ip=request.remote_addr or "-",
                username=g.usuario['username'],
                action="Cuenta del remitente no encontrada",
                http_code=404
            )
            api.abort(404, "Cuenta del remitente no encontrada")
        
        balance_remitente = float(fila[0])
        
        if balance_remitente < monto:
            cursor.close()
            conexion.close()
            write_custom_log(
                log_type="WARNING",
                remote_ip=request.remote_addr or "-",
                username=g.usuario['username'],
                action=f"Fondos insuficientes para transferencia: {monto} (balance: {balance_remitente})",
                http_code=400
            )
            api.abort(400, "Fondos insuficientes")
        
        # Buscar usuario destino
        cursor.execute("SELECT id FROM bank.users WHERE username = %s", (usuario_destino,))
        usuario_objetivo = cursor.fetchone()
        
        if not usuario_objetivo:
            cursor.close()
            conexion.close()
            write_custom_log(
                log_type="WARNING",
                remote_ip=request.remote_addr or "-",
                username=g.usuario['username'],
                action=f"Usuario destino no encontrado: {usuario_destino}",
                http_code=404
            )
            api.abort(404, "Usuario destino no encontrado")
        
        id_usuario_objetivo = usuario_objetivo[0]
        
        try:
            cursor.execute("UPDATE bank.accounts SET balance = balance - %s WHERE user_id = %s", 
                         (monto, g.usuario['id']))
            cursor.execute("UPDATE bank.accounts SET balance = balance + %s WHERE user_id = %s", 
                         (monto, id_usuario_objetivo))
            cursor.execute("SELECT balance FROM bank.accounts WHERE user_id = %s", (g.usuario['id'],))
            nuevo_balance = float(cursor.fetchone()[0])
            conexion.commit()
            write_custom_log(
                log_type="INFO",
                remote_ip=request.remote_addr or "-",
                username=g.usuario['username'],
                action=f"Transferencia exitosa: ${monto} a {usuario_destino}",
                http_code=200
            )
        except Exception as e:
            conexion.rollback()
            cursor.close()
            conexion.close()
            write_custom_log(
                log_type="ERROR",
                remote_ip=request.remote_addr or "-",
                username=g.usuario['username'],
                action=f"Error en transferencia: {str(e)}",
                http_code=500
            )
            api.abort(500, f"Error durante la transferencia: {str(e)}")
        
        cursor.close()
        conexion.close()
        return {"message": "Transferencia exitosa", "new_balance": nuevo_balance}, 200

@bank_ns.route('/credit-payment')
class CreditPayment(Resource):
    @bank_ns.expect(credit_payment_model, validate=True)
    @bank_ns.doc('credit_payment')
    @token_required
    def post(self):
        """
        Realiza una compra a crédito:
        - Descuenta el monto de la cuenta.
        - Aumenta la deuda de la tarjeta de crédito.
        """
        write_custom_log(
            log_type="INFO",
            remote_ip=request.remote_addr or "-",
            username=g.usuario['username'],
            action="Operación de pago con crédito iniciada",
            http_code=0
        )
        
        datos = api.payload
        monto = datos.get("amount", 0)
        
        if monto <= 0:
            write_custom_log(
                log_type="WARNING",
                remote_ip=request.remote_addr or "-",
                username=g.usuario['username'],
                action=f"Monto de pago con crédito inválido: {monto}",
                http_code=400
            )
            api.abort(400, "El monto debe ser mayor que cero")
        
        id_usuario = g.usuario['id']
        conexion = get_connection()
        cursor = conexion.cursor()
        
        cursor.execute("SELECT balance FROM bank.accounts WHERE user_id = %s", (id_usuario,))
        fila = cursor.fetchone()
        
        if not fila:
            cursor.close()
            conexion.close()
            write_custom_log(
                log_type="ERROR",
                remote_ip=request.remote_addr or "-",
                username=g.usuario['username'],
                action="Cuenta no encontrada para pago con crédito",
                http_code=404
            )
            api.abort(404, "Cuenta no encontrada")
        
        balance_cuenta = float(fila[0])
        
        if balance_cuenta < monto:
            cursor.close()
            conexion.close()
            write_custom_log(
                log_type="WARNING",
                remote_ip=request.remote_addr or "-",
                username=g.usuario['username'],
                action=f"Fondos insuficientes para pago con crédito: {monto} (balance: {balance_cuenta})",
                http_code=400
            )
            api.abort(400, "Fondos insuficientes en cuenta")
        
        try:
            cursor.execute("UPDATE bank.accounts SET balance = balance - %s WHERE user_id = %s", 
                         (monto, id_usuario))
            cursor.execute("UPDATE bank.credit_cards SET balance = balance + %s WHERE user_id = %s", 
                         (monto, id_usuario))
            cursor.execute("SELECT balance FROM bank.accounts WHERE user_id = %s", (id_usuario,))
            nuevo_balance_cuenta = float(cursor.fetchone()[0])
            cursor.execute("SELECT balance FROM bank.credit_cards WHERE user_id = %s", (id_usuario,))
            nuevo_balance_credito = float(cursor.fetchone()[0])
            conexion.commit()
            write_custom_log(
                log_type="INFO",
                remote_ip=request.remote_addr or "-",
                username=g.usuario['username'],
                action=f"Pago con crédito exitoso: ${monto}",
                http_code=200
            )
        except Exception as e:
            conexion.rollback()
            cursor.close()
            conexion.close()
            write_custom_log(
                log_type="ERROR",
                remote_ip=request.remote_addr or "-",
                username=g.usuario['username'],
                action=f"Error en pago con crédito: {str(e)}",
                http_code=500
            )
            api.abort(500, f"Error procesando compra con tarjeta de crédito: {str(e)}")
        
        cursor.close()
        conexion.close()
        return {
            "message": "Compra con tarjeta de crédito exitosa",
            "account_balance": nuevo_balance_cuenta,
            "credit_card_debt": nuevo_balance_credito
        }, 200

@bank_ns.route('/pay-credit-balance')
class PayCreditBalance(Resource):
    @bank_ns.expect(pay_credit_balance_model, validate=True)
    @bank_ns.doc('pay_credit_balance')
    @token_required
    def post(self):
        """
        Realiza un abono a la deuda de la tarjeta:
        - Descuenta el monto (o el máximo posible) de la cuenta.
        - Reduce la deuda de la tarjeta de crédito.
        """
        write_custom_log(
            log_type="INFO",
            remote_ip=request.remote_addr or "-",
            username=g.usuario['username'],
            action="Operación de pago de deuda de crédito iniciada",
            http_code=0
        )
        
        datos = api.payload
        monto = datos.get("amount", 0)
        
        if monto <= 0:
            write_custom_log(
                log_type="WARNING",
                remote_ip=request.remote_addr or "-",
                username=g.usuario['username'],
                action=f"Monto de pago de deuda inválido: {monto}",
                http_code=400
            )
            api.abort(400, "El monto debe ser mayor que cero")
        
        id_usuario = g.usuario['id']
        conexion = get_connection()
        cursor = conexion.cursor()
        
        # Verificar fondos en cuenta
        cursor.execute("SELECT balance FROM bank.accounts WHERE user_id = %s", (id_usuario,))
        fila = cursor.fetchone()
        
        if not fila:
            cursor.close()
            conexion.close()
            write_custom_log(
                log_type="ERROR",
                remote_ip=request.remote_addr or "-",
                username=g.usuario['username'],
                action="Cuenta no encontrada para pago de deuda",
                http_code=404
            )
            api.abort(404, "Cuenta no encontrada")
        
        balance_cuenta = float(fila[0])
        
        if balance_cuenta < monto:
            cursor.close()
            conexion.close()
            write_custom_log(
                log_type="WARNING",
                remote_ip=request.remote_addr or "-",
                username=g.usuario['username'],
                action=f"Fondos insuficientes para pago de deuda: {monto} (balance: {balance_cuenta})",
                http_code=400
            )
            api.abort(400, "Fondos insuficientes en cuenta")
        
        # Obtener deuda actual de tarjeta de crédito
        cursor.execute("SELECT balance FROM bank.credit_cards WHERE user_id = %s", (id_usuario,))
        fila = cursor.fetchone()
        
        if not fila:
            cursor.close()
            conexion.close()
            write_custom_log(
                log_type="ERROR",
                remote_ip=request.remote_addr or "-",
                username=g.usuario['username'],
                action="Tarjeta de crédito no encontrada",
                http_code=404
            )
            api.abort(404, "Tarjeta de crédito no encontrada")
        
        deuda_credito = float(fila[0])
        pago = min(monto, deuda_credito)
        
        try:
            cursor.execute("UPDATE bank.accounts SET balance = balance - %s WHERE user_id = %s", 
                         (pago, id_usuario))
            cursor.execute("UPDATE bank.credit_cards SET balance = balance - %s WHERE user_id = %s", 
                         (pago, id_usuario))
            cursor.execute("SELECT balance FROM bank.accounts WHERE user_id = %s", (id_usuario,))
            nuevo_balance_cuenta = float(cursor.fetchone()[0])
            cursor.execute("SELECT balance FROM bank.credit_cards WHERE user_id = %s", (id_usuario,))
            nueva_deuda_credito = float(cursor.fetchone()[0])
            conexion.commit()
            write_custom_log(
                log_type="INFO",
                remote_ip=request.remote_addr or "-",
                username=g.usuario['username'],
                action=f"Pago de deuda exitoso: ${pago}",
                http_code=200
            )
        except Exception as e:
            conexion.rollback()
            cursor.close()
            conexion.close()
            write_custom_log(
                log_type="ERROR",
                remote_ip=request.remote_addr or "-",
                username=g.usuario['username'],
                action=f"Error en pago de deuda: {str(e)}",
                http_code=500
            )
            api.abort(500, f"Error procesando pago de deuda de tarjeta: {str(e)}")
        
        cursor.close()
        conexion.close()
        return {
            "message": "Pago de deuda de tarjeta exitoso",
            "account_balance": nuevo_balance_cuenta,
            "credit_card_debt": nueva_deuda_credito
        }, 200

@app.before_first_request
def initialize_db():
    init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)

