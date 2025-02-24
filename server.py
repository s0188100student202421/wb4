from http.server import BaseHTTPRequestHandler, HTTPServer
import mysql.connector
import cgi
import re
import secrets
from http import cookies
import json
import base64

def safe_base64_encode(data):
    return base64.urlsafe_b64encode(data.encode('utf-8')).decode('utf-8')

def safe_base64_decode(data):
    missing_padding = len(data) % 4
    if missing_padding:
        data += "=" * (4 - missing_padding)  # Добавляем недостающие =
    return base64.urlsafe_b64decode(data).decode("utf-8")



class HttpProcessor(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        cookie = cookies.SimpleCookie(self.headers.get('Cookie'))
        token = cookie.get('form_token')
        token = token.value if token else ""

        if not cookie.get('form_token'):
            token = secrets.token_hex(16)
            cookie['form_token'] = token
            cookie['form_token']['path'] = '/'
            cookie['form_token']['max-age'] = 3600
            cookie['form_token']['httponly'] = True
            self.send_header('Set-Cookie', cookie.output(header='', sep=''))
        self.end_headers()

        with open('index.html', 'r', encoding='utf-8') as file:  
            html_content = file.read().replace("{{form_token}}", token)
        
        form_data = {
            'fio': cookie.get('fio'),
            'phone': cookie.get('phone'),
            'email': cookie.get('email'),
            'date': cookie.get('date'),
            'bio': cookie.get('bio'),
            'languages': cookie.get('languages'),
            'gender': cookie.get('gender'),
            'check': cookie.get('check')
        }


        for field, value in form_data.items():
            if value:
                if isinstance(value, cookies.Morsel):
                    html_content = html_content.replace(f"{{{{{field}}}}}", safe_base64_decode(value.value))
                else:
                    html_content = html_content.replace(f"{{{{{field}}}}}", safe_base64_decode(value))
            else:
                html_content = html_content.replace(f"{{{{{field}}}}}", "")


        errors = cookie.get('errors')
        if errors:
            decoded_errors = safe_base64_decode(errors.value)
            fixed_error = decoded_errors.replace("'", '"')
            error_dict = json.loads(fixed_error) 
            for field, error in error_dict.items():
                html_content = html_content.replace(f'{{{{{field}}}}}', f'<input type="text" name="{field}" value="{form_data.get(field)}" class="error">')
                html_content = html_content.replace(f"{{{{error_{field}}}}}", f'<span class="error">{error}</span>')

            for field in ['fio', 'phone', 'email', 'bio', 'languages', 'gender', 'check']:
                if field not in error_dict:
                    html_content = html_content.replace(f"{{{{error_{field}}}}}", "")
        else:
            for field in ['fio', 'phone', 'email', 'bio', 'languages', 'gender', 'check']:
                html_content = html_content.replace(f"{{{{error_{field}}}}}", " ")
        self.wfile.write(html_content.encode('utf-8')) 


    def do_POST(self):
        cookie = cookies.SimpleCookie(self.headers.get('Cookie'))
        stored_token = cookie.get('form_token', None)
        

        if not stored_token:
            self.send_response(403)
            self.end_headers()
            self.wfile.write("CSRF token missing".encode('utf-8'))
            return

        form = cgi.FieldStorage(
            fp=self.rfile,
            headers=self.headers,
            environ={'REQUEST_METHOD': 'POST'}
        )

        from_token = form.getvalue('form_token')
        fio = form.getvalue('fio')
        phone = form.getvalue('phone')
        email = form.getvalue('email')
        date = form.getvalue('date')
        gender = form.getvalue('gender')
        languages = form.getlist('languages')
        bio = form.getvalue('bio')
        check = form.getvalue('check')

        errors = {}
        valid_fio = re.compile(r"^[A-Za-zА-Яа-яЁё ]+$")
        if not fio or not valid_fio.match(fio) or len(fio) > 150:
            errors["fio"] = "Недопустимые символы в поле 'ФИО'. Разрешены только буквы и пробелы."

        valid_phone = re.compile(r"^(?:\+7|8)[0-9]{10}$")
        if not phone or not valid_phone.match(phone):
            errors["phone"] = "Неверный номер телефона. Используйте формат +7XXXXXXXXXX."

        valid_email = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
        if not email or not valid_email.match(email):
            errors["email"] = "Неверный email. Используйте формат example@domain.com."

        if not gender:
            errors["gender"] = "Не выбран пол."

        if not languages:
            errors["languages"] = "Не выбран ни один язык программирования."

        if not bio or len(bio) > 500:
            errors["bio"] = "Неверная биография. Максимальная длина 500 символов."

        if not check:
            errors["check"] = "Необходимо согласие с контрактом."

        if errors:
            cookie = cookies.SimpleCookie()
            for field in ['fio', 'phone', 'email', 'date', 'bio', 'gender', 'check']:
                    value = locals().get(field, '')
                    if value:
                        cookie[field] = safe_base64_encode(value)
                        cookie[field]['path'] = '/'  
                        cookie[field]['httponly'] = True  
                        cookie[field]['max-age'] = 31536000  
            if languages:
                cookie['languages'] = safe_base64_encode(",".join(languages))
                cookie['languages']['path'] = '/'
                cookie['languages']['httponly'] = True
                cookie['languages']['max-age'] = 31536000

            cookie["errors"] = safe_base64_encode(str(errors))
            cookie["errors"]['path'] = '/'
            cookie["errors"]['httponly'] = True
            cookie["errors"]['max-age'] = 3600

            self.send_response(302)
            self.send_header('Location', self.path)
            for key, morsel in cookie.items():
                self.send_header('Set-Cookie', morsel.OutputString())
            self.end_headers()
            return
        try:
            connection = mysql.connector.connect(
                host='localhost',
                database='u68824',
                user='u68824',
                password='MyStrongPass'
            )

            if connection.is_connected():
                cursor = connection.cursor()
                cursor.execute("""
                    INSERT INTO applications(full_name, gender, phone, email, date, bio, agreement)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                """, (fio, gender, phone, email, date, bio, bool(check)))

                user_id = cursor.lastrowid
                for lang in languages:
                    cursor.execute("""
                        INSERT INTO programming_languages (id, name)
                        VALUES (%s, %s)
                    """, (user_id, lang))

                connection.commit()
                cursor.close()
                connection.close()
                self.send_response(200)
                cookie = cookies.SimpleCookie()
                for field in ['fio', 'phone', 'email', 'date', 'bio', 'gender', 'check']:
                    value = locals().get(field, '')
                    if value:
                        cookie[field] = safe_base64_encode(value)
                        cookie[field]['path'] = '/'  
                        cookie[field]['httponly'] = True  
                        cookie[field]['max-age'] = 31536000  

                if languages:
                    cookie['languages'] = safe_base64_encode(",".join(languages))
                    cookie['languages']['path'] = '/'
                    cookie['languages']['httponly'] = True
                    cookie['languages']['max-age'] = 31536000

                cookie['errors'] = ''
                cookie['errors']['path'] = '/'
                cookie['errors']['max-age'] = 0

                self.send_response(200)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                for key, morsel in cookie.items():
                    self.send_header('Set-Cookie', morsel.OutputString())
                self.end_headers()
                self.wfile.write(f"Data successfully sent!".encode('utf-8'))


        except Error as e:
            self.send_response(500)
            self.end_headers()
            self.wfile.write(f"Database error: {e}".encode('utf-8'))


# Запуск сервера
serv = HTTPServer(("localhost", 8888), HttpProcessor)
serv.serve_forever()
