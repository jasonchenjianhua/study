import json
import secrets
import sqlite3
from hashlib import pbkdf2_hmac
from http import cookies
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DB_PATH = DATA_DIR / "app.db"
SESSION_COOKIE = "study_session"
DEFAULT_TASKS = [
    ("英语阅读", 3.0),
    ("单词默写", 2.0),
    ("专注打卡", 2.5),
]


def ensure_database():
    DATA_DIR.mkdir(exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                balance REAL NOT NULL DEFAULT 0,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                price REAL NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                log_date TEXT NOT NULL,
                description TEXT NOT NULL,
                amount REAL NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
            """
        )
        user_columns = {
            row[1] for row in conn.execute("PRAGMA table_info(users)").fetchall()
        }
        if "balance" not in user_columns:
            conn.execute("ALTER TABLE users ADD COLUMN balance REAL NOT NULL DEFAULT 0")
        conn.commit()


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def hash_password(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 120000).hex()
    return f"{salt}${digest}"


def verify_password(password, stored_value):
    salt, stored_hash = stored_value.split("$", 1)
    return hash_password(password, salt) == f"{salt}${stored_hash}"


def today_string():
    with get_connection() as conn:
        row = conn.execute("SELECT strftime('%Y-%m-%d', 'now', 'localtime') AS today").fetchone()
    return row["today"]


def rank_name(balance):
    if balance > 500:
        return "高级精英"
    if balance > 200:
        return "中级理财师"
    return "初级自律者"


class AppHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self.cookie_to_set = None
        self.cookie_to_clear = False
        super().__init__(*args, directory=str(BASE_DIR), **kwargs)

    def log_message(self, format, *args):
        return

    def end_headers(self):
        if self.cookie_to_set:
            self.send_header("Set-Cookie", self.cookie_to_set)
        if self.cookie_to_clear:
            self.send_header(
                "Set-Cookie",
                f"{SESSION_COOKIE}=; Path=/; HttpOnly; Max-Age=0; SameSite=Lax",
            )
        super().end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/session":
            return self.handle_session()
        if parsed.path == "/api/app-state":
            return self.handle_app_state()
        return super().do_GET()

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/register":
            return self.handle_register()
        if parsed.path == "/api/login":
            return self.handle_login()
        if parsed.path == "/api/logout":
            return self.handle_logout()
        if parsed.path == "/api/tasks":
            return self.handle_task_create()
        if parsed.path == "/api/logs/income":
            return self.handle_income_create()
        if parsed.path == "/api/logs/rank-up":
            return self.handle_rank_up()
        if parsed.path == "/api/logs/expense":
            return self.handle_expense_create()
        self.send_json({"error": "Not found"}, status=404)

    def do_DELETE(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/tasks":
            task_ids = parse_qs(parsed.query).get("id", [])
            if not task_ids:
                return self.send_json({"error": "缺少任务 id"}, status=400)
            return self.handle_task_delete(task_ids[0])
        if parsed.path == "/api/logs":
            log_ids = parse_qs(parsed.query).get("id", [])
            if not log_ids:
                return self.send_json({"error": "缺少记录 id"}, status=400)
            return self.handle_log_delete(log_ids[0])
        self.send_json({"error": "Not found"}, status=404)

    def parse_json(self):
        length = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(length) if length else b"{}"
        try:
            return json.loads(raw_body.decode("utf-8"))
        except json.JSONDecodeError:
            return None

    def send_json(self, payload, status=200):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def get_session_token(self):
        cookie_header = self.headers.get("Cookie")
        if not cookie_header:
            return None
        jar = cookies.SimpleCookie()
        jar.load(cookie_header)
        morsel = jar.get(SESSION_COOKIE)
        return morsel.value if morsel else None

    def get_current_user(self):
        token = self.get_session_token()
        if not token:
            return None
        with get_connection() as conn:
            row = conn.execute(
                """
                SELECT users.id, users.username, users.balance, users.created_at
                FROM sessions
                JOIN users ON users.id = sessions.user_id
                WHERE sessions.token = ?
                """,
                (token,),
            ).fetchone()
        return dict(row) if row else None

    def require_user(self):
        user = self.get_current_user()
        if not user:
            self.send_json({"error": "未登录"}, status=401)
            return None
        return user

    def create_session(self, user_id):
        token = secrets.token_urlsafe(32)
        with get_connection() as conn:
            conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
            conn.execute("INSERT INTO sessions (token, user_id) VALUES (?, ?)", (token, user_id))
            conn.commit()
        self.cookie_to_set = f"{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=604800"

    def seed_default_tasks(self, conn, user_id):
        conn.executemany(
            "INSERT INTO tasks (user_id, name, price) VALUES (?, ?, ?)",
            [(user_id, name, price) for name, price in DEFAULT_TASKS],
        )

    def fetch_app_state(self, user_id):
        with get_connection() as conn:
            user = conn.execute(
                "SELECT id, username, balance, created_at FROM users WHERE id = ?",
                (user_id,),
            ).fetchone()
            tasks = conn.execute(
                "SELECT id, name, price FROM tasks WHERE user_id = ? ORDER BY id ASC",
                (user_id,),
            ).fetchall()
            logs = conn.execute(
                """
                SELECT id, log_date AS date, description AS desc, amount
                FROM logs
                WHERE user_id = ?
                ORDER BY id DESC
                """,
                (user_id,),
            ).fetchall()

        balance = float(user["balance"])
        return {
            "user": {
                "id": user["id"],
                "username": user["username"],
                "balance": balance,
                "rank": rank_name(balance),
                "created_at": user["created_at"],
            },
            "tasks": [dict(row) for row in tasks],
            "logs": [dict(row) for row in logs],
        }

    def change_balance_and_add_log(self, user_id, amount, description):
        log_date = today_string()
        with get_connection() as conn:
            user = conn.execute("SELECT balance FROM users WHERE id = ?", (user_id,)).fetchone()
            if user is None:
                return None, "用户不存在"
            new_balance = float(user["balance"]) + float(amount)
            if new_balance < 0:
                return None, "余额不足"
            conn.execute("UPDATE users SET balance = ? WHERE id = ?", (new_balance, user_id))
            conn.execute(
                "INSERT INTO logs (user_id, log_date, description, amount) VALUES (?, ?, ?, ?)",
                (user_id, log_date, description, float(amount)),
            )
            conn.commit()
        return self.fetch_app_state(user_id), None

    def handle_register(self):
        payload = self.parse_json()
        if payload is None:
            return self.send_json({"error": "请求格式错误"}, status=400)

        username = (payload.get("username") or "").strip()
        password = payload.get("password") or ""
        if len(username) < 3 or len(password) < 6:
            return self.send_json({"error": "用户名至少 3 位，密码至少 6 位"}, status=400)

        try:
            with get_connection() as conn:
                cursor = conn.execute(
                    "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                    (username, hash_password(password)),
                )
                user_id = cursor.lastrowid
                self.seed_default_tasks(conn, user_id)
                conn.commit()
        except sqlite3.IntegrityError:
            return self.send_json({"error": "用户名已存在"}, status=409)

        self.create_session(user_id)
        self.send_json(
            {
                "message": "注册成功",
                "state": self.fetch_app_state(user_id),
            },
            status=201,
        )

    def handle_login(self):
        payload = self.parse_json()
        if payload is None:
            return self.send_json({"error": "请求格式错误"}, status=400)

        username = (payload.get("username") or "").strip()
        password = payload.get("password") or ""
        with get_connection() as conn:
            user = conn.execute(
                "SELECT id, password_hash FROM users WHERE username = ?",
                (username,),
            ).fetchone()

        if not user or not verify_password(password, user["password_hash"]):
            return self.send_json({"error": "用户名或密码错误"}, status=401)

        self.create_session(user["id"])
        self.send_json({"message": "登录成功", "state": self.fetch_app_state(user["id"])})

    def handle_logout(self):
        token = self.get_session_token()
        if token:
            with get_connection() as conn:
                conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
                conn.commit()
        self.cookie_to_clear = True
        self.send_json({"message": "已退出登录"})

    def handle_session(self):
        user = self.get_current_user()
        if not user:
            return self.send_json({"authenticated": False})
        self.send_json({"authenticated": True, "state": self.fetch_app_state(user["id"])})

    def handle_app_state(self):
        user = self.require_user()
        if not user:
            return
        self.send_json({"state": self.fetch_app_state(user["id"])})

    def handle_task_create(self):
        user = self.require_user()
        if not user:
            return
        payload = self.parse_json()
        if payload is None:
            return self.send_json({"error": "请求格式错误"}, status=400)

        name = (payload.get("name") or "").strip()
        price = payload.get("price")
        try:
            price = float(price)
        except (TypeError, ValueError):
            return self.send_json({"error": "请填写正确金额"}, status=400)
        if not name:
            return self.send_json({"error": "请填写任务名称"}, status=400)

        with get_connection() as conn:
            conn.execute(
                "INSERT INTO tasks (user_id, name, price) VALUES (?, ?, ?)",
                (user["id"], name, price),
            )
            conn.commit()
        self.send_json({"message": "任务已添加", "state": self.fetch_app_state(user["id"])}, status=201)

    def handle_task_delete(self, task_id):
        user = self.require_user()
        if not user:
            return
        with get_connection() as conn:
            deleted = conn.execute(
                "DELETE FROM tasks WHERE id = ? AND user_id = ?",
                (task_id, user["id"]),
            ).rowcount
            conn.commit()
        if not deleted:
            return self.send_json({"error": "任务不存在"}, status=404)
        self.send_json({"message": "任务已删除", "state": self.fetch_app_state(user["id"])})

    def handle_income_create(self):
        user = self.require_user()
        if not user:
            return
        payload = self.parse_json()
        if payload is None:
            return self.send_json({"error": "请求格式错误"}, status=400)

        description = (payload.get("description") or "").strip()
        amount = payload.get("amount")
        try:
            amount = float(amount)
        except (TypeError, ValueError):
            return self.send_json({"error": "金额格式错误"}, status=400)
        if amount <= 0:
            return self.send_json({"error": "金额必须大于 0"}, status=400)

        state, error = self.change_balance_and_add_log(user["id"], amount, description)
        if error:
            return self.send_json({"error": error}, status=400)
        self.send_json({"message": "入账成功", "state": state}, status=201)

    def handle_rank_up(self):
        user = self.require_user()
        if not user:
            return
        payload = self.parse_json()
        if payload is None:
            return self.send_json({"error": "请求格式错误"}, status=400)

        try:
            steps = int(payload.get("steps"))
        except (TypeError, ValueError):
            return self.send_json({"error": "请输入正确名次数"}, status=400)
        if steps <= 0:
            return self.send_json({"error": "请输入大于 0 的名次数"}, status=400)

        bonus = steps * 10
        state, error = self.change_balance_and_add_log(user["id"], bonus, f"名次提升{steps}名")
        if error:
            return self.send_json({"error": error}, status=400)
        self.send_json({"message": "奖励已入账", "state": state}, status=201)

    def handle_expense_create(self):
        user = self.require_user()
        if not user:
            return
        payload = self.parse_json()
        if payload is None:
            return self.send_json({"error": "请求格式错误"}, status=400)

        name = (payload.get("name") or "").strip()
        amount = payload.get("amount")
        try:
            amount = float(amount)
        except (TypeError, ValueError):
            return self.send_json({"error": "金额格式错误"}, status=400)
        if not name:
            return self.send_json({"error": "请填写消费名称"}, status=400)
        if amount <= 0:
            return self.send_json({"error": "金额必须大于 0"}, status=400)

        state, error = self.change_balance_and_add_log(user["id"], -amount, f"支出：{name}")
        if error:
            return self.send_json({"error": error}, status=400)
        self.send_json({"message": "支出已记录", "state": state}, status=201)

    def handle_log_delete(self, log_id):
        user = self.require_user()
        if not user:
            return
        with get_connection() as conn:
            log = conn.execute(
                "SELECT amount FROM logs WHERE id = ? AND user_id = ?",
                (log_id, user["id"]),
            ).fetchone()
            if log is None:
                return self.send_json({"error": "记录不存在"}, status=404)

            user_row = conn.execute("SELECT balance FROM users WHERE id = ?", (user["id"],)).fetchone()
            new_balance = float(user_row["balance"]) - float(log["amount"])
            if new_balance < 0:
                return self.send_json({"error": "删除后余额会异常，无法删除"}, status=400)

            conn.execute("UPDATE users SET balance = ? WHERE id = ?", (new_balance, user["id"]))
            conn.execute("DELETE FROM logs WHERE id = ? AND user_id = ?", (log_id, user["id"]))
            conn.commit()
        self.send_json({"message": "记录已删除", "state": self.fetch_app_state(user["id"])})


def main():
    ensure_database()
    server = ThreadingHTTPServer(("127.0.0.1", 8000), AppHandler)
    print("Server running at http://127.0.0.1:8000")
    server.serve_forever()


if __name__ == "__main__":
    main()
