# file: src/users/validators.py
from typing import Tuple
import hashlib
import secrets
import base64
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError


class PasswordValidator:
    """
    Валидатор паролей с использованием Argon2id.
    Argon2 - победитель Password Hashing Competition 2015.
    """
    
    # Конфигурация Argon2 (рекомендованные значения OWASP)
    _ph = PasswordHasher(
        time_cost=3,      # Количество итераций
        memory_cost=65536, # Память в KiB (64MB)
        parallelism=4,     # Параллельные потоки
        hash_len=32,       # Длина хеша
        salt_len=16        # Длина соли
    )
    
    @staticmethod
    def hash_password(password: str) -> str:
        """
        Хеширование пароля с использованием Argon2id.
        
        Args:
            password: Пароль в виде строки
            
        Returns:
            Хешированный пароль в формате Argon2
        """
        if not password or len(password) < 8:
            raise ValueError("Password must be at least 8 characters long")
        
        # Argon2 автоматически генерирует соль и включает ее в хеш
        return PasswordValidator._ph.hash(password)
    
    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """
        Верификация пароля.
        
        Args:
            plain_password: Пароль для проверки
            hashed_password: Хешированный пароль из БД
            
        Returns:
            True если пароль верный, False если нет
        """
        try:
            return PasswordValidator._ph.verify(hashed_password, plain_password)
        except (VerifyMismatchError, InvalidHashError):
            return False
    
    @staticmethod
    def needs_rehash(hashed_password: str) -> bool:
        """
        Проверка, нужно ли перехешировать пароль.
        Полезно при изменении параметров хеширования.
        
        Args:
            hashed_password: Хешированный пароль
            
        Returns:
            True если параметры хеширования устарели
        """
        return PasswordValidator._ph.check_needs_rehash(hashed_password)
    
    @staticmethod
    def generate_secure_password(length: int = 16) -> str:
        """
        Генерация безопасного случайного пароля.
        
        Args:
            length: Длина пароля
            
        Returns:
            Случайный пароль
        """
        alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
        return ''.join(secrets.choice(alphabet) for _ in range(length))
    
    @staticmethod
    def get_password_strength(password: str) -> Tuple[int, str]:
        """
        Оценка сложности пароля.
        
        Returns:
            Tuple (score 0-4, description)
        """
        score = 0
        remarks = []
        
        if len(password) >= 12:
            score += 1
        else:
            remarks.append("Используйте не менее 12 символов")
        
        if any(c.islower() for c in password):
            score += 1
        else:
            remarks.append("Добавьте строчные буквы")
            
        if any(c.isupper() for c in password):
            score += 1
        else:
            remarks.append("Добавьте заглавные буквы")
            
        if any(c.isdigit() for c in password):
            score += 1
        else:
            remarks.append("Добавьте цифры")
            
        if any(c in "!@#$%^&*" for c in password):
            score += 1
        else:
            remarks.append("Добавьте спецсимволы")
        
        strength = {
            0: ("Очень слабый", "danger"),
            1: ("Слабый", "warning"),
            2: ("Средний", "info"),
            3: ("Хороший", "primary"),
            4: ("Отличный", "success"),
            5: ("Идеальный", "success")
        }
        
        desc, level = strength.get(score, ("Неизвестно", "secondary"))
        
        if remarks:
            advice = " | ".join(remarks[:2])
        else:
            advice = "Пароль достаточно надежный"
            
        return score, f"{desc} - {advice}"


# Альтернатива: PBKDF2 (если Argon2 недоступен)
class PBKDF2PasswordValidator:
    """Резервный валидатор на случай если Argon2 не установлен"""
    
    @staticmethod
    def hash_password(password: str, iterations: int = 310000) -> str:
        """
        Хеширование с использованием PBKDF2-HMAC-SHA256.
        
        Формат: algorithm:iterations:salt:hash
        """
        salt = secrets.token_bytes(16)
        hash_bytes = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            iterations
        )
        
        # Кодируем в формат: algorithm:iterations:salt:hash
        return f"pbkdf2_sha256:{iterations}:{base64.b64encode(salt).decode()}:{base64.b64encode(hash_bytes).decode()}"
    
    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """Верификация PBKDF2 хеша"""
        try:
            algorithm, iterations, salt_b64, hash_b64 = hashed_password.split(':')
            if algorithm != 'pbkdf2_sha256':
                return False
                
            salt = base64.b64decode(salt_b64)
            expected_hash = base64.b64decode(hash_b64)
            
            actual_hash = hashlib.pbkdf2_hmac(
                'sha256',
                plain_password.encode('utf-8'),
                salt,
                int(iterations)
            )
            
            return secrets.compare_digest(actual_hash, expected_hash)
        except (ValueError, TypeError):
            return False


# Экспорт основного валидатора
password_validator = PasswordValidator()
