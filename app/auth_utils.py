# app/auth_utils.py
from functools import wraps
from flask import g, request
from flask_restx import abort

def cajero_required(f):
    """
    Decorador que requiere que el usuario autenticado sea un cajero
    """
    @wraps(f)
    def decorador(*args, **kwargs):
        # Verificar que el usuario esté autenticado
        if not hasattr(g, 'usuario') or not g.usuario:
            abort(401, "Autenticación requerida")
        
        # Verificar que el usuario sea un cajero
        if g.usuario.get('role') != 'cajero':
            from .custom_logger import write_custom_log
            write_custom_log(
                log_type="WARNING",
                remote_ip=request.remote_addr or "-",
                username=g.usuario.get('username', '-'),
                action=f"Acceso denegado - rol {g.usuario.get('role')} intentó acceder a endpoint de cajero",
                http_code=403
            )
            abort(403, "Acceso denegado. Solo los cajeros pueden acceder a este endpoint.")
        
        return f(*args, **kwargs)
    
    return decorador

def role_required(required_role):
    """
    Decorador genérico que requiere un rol específico
    """
    def decorator(f):
        @wraps(f)
        def decorador(*args, **kwargs):
            # Verificar que el usuario esté autenticado
            if not hasattr(g, 'usuario') or not g.usuario:
                abort(401, "Autenticación requerida")
            
            # Verificar que el usuario tenga el rol requerido
            if g.usuario.get('role') != required_role:
                from .custom_logger import write_custom_log
                write_custom_log(
                    log_type="WARNING",
                    remote_ip=request.remote_addr or "-",
                    username=g.usuario.get('username', '-'),
                    action=f"Acceso denegado - rol {g.usuario.get('role')} intentó acceder a endpoint que requiere rol {required_role}",
                    http_code=403
                )
                abort(403, f"Acceso denegado. Se requiere rol: {required_role}")
            
            return f(*args, **kwargs)
        
        return decorador
    return decorator