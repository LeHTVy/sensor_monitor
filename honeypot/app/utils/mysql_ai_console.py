#!/usr/bin/env python3
"""
Stateful MySQL-like console for Honeypot
 - Rule-based simulator for core commands
 - Optional Ollama integration via HTTP for richer realism (disabled by default)

Behavior goals:
 - No explanations; return raw console-like output
 - Maintain state per session_id
 - Always end output with prompt: "mysql> "
"""

from __future__ import annotations

import os
import json
import re
from typing import Dict, List, Any
import requests
from datetime import datetime


class MySQLAIConsole:
    def __init__(self):
        self.default_db = 'admin_panel'
        # Session state: session_id -> state
        self.sessions: Dict[str, Dict[str, Any]] = {}
        self.use_ollama = os.getenv('USE_OLLAMA', 'false').lower() == 'true'
        self.ollama_url = os.getenv('OLLAMA_URL', 'http://localhost:11434')
        self.ollama_model = os.getenv('OLLAMA_MODEL', 'qwen2.5:7b')

    def _init_session(self, session_id: str):
        if session_id in self.sessions:
            return
        # Initialize with three default tables and fake rows
        self.sessions[session_id] = {
            'current_db': self.default_db,
            'schemas': {
                'users': ['id', 'username', 'email', 'role'],
                'products': ['id', 'name', 'price', 'stock'],
                'orders': ['id', 'user_id', 'product_id', 'quantity', 'total'],
            },
            'rows': {
                'users': [
                    [1, 'admin', 'admin@company.com', 'Administrator'],
                    [2, 'john', 'john@company.com', 'User'],
                    [3, 'sarah', 'sarah@company.com', 'Manager'],
                ],
                'products': [
                    [1, 'Product A', 100, 50],
                    [2, 'Product B', 200, 30],
                    [3, 'Product C', 150, 75],
                ],
                'orders': [
                    [1, 1, 1, 2, 200],
                    [2, 2, 2, 1, 200],
                ],
            },
        }

    def _prompt(self) -> str:
        return 'mysql> '

    def _err(self) -> str:
        return f"ERROR 1064 (42000): You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '' at line 1\n{self._prompt()}"

    def _ok(self, message: str | None = None) -> str:
        prefix = 'Query OK, 1 row affected' if message is None else message
        return f"{prefix}\n{self._prompt()}"

    def _render_table(self, headers: List[str], rows: List[List[Any]]) -> str:
        # Simple ASCII table rendering
        widths = [len(h) for h in headers]
        for r in rows:
            for i, c in enumerate(r):
                widths[i] = max(widths[i], len(str(c)))
        def draw_row(cols: List[Any]) -> str:
            return '| ' + ' | '.join(str(c).ljust(widths[i]) for i, c in enumerate(cols)) + ' |'
        sep = '+-' + '-+-'.join('-' * w for w in widths) + '-+'
        lines = [sep, draw_row(headers), sep]
        for r in rows:
            lines.append(draw_row([str(c) for c in r]))
        lines.append(sep)
        return '\n'.join(lines)

    def handle_command(self, cmd: str, session_id: str) -> str:
        self._init_session(session_id)
        state = self.sessions[session_id]
        s = cmd.strip().rstrip(';')
        if not s:
            return self._prompt()

        upper = s.upper()

        # Non-SQL chat → syntax error
        if not re.search(r"^(SELECT|SHOW|DESCRIBE|DESC|CREATE|INSERT|UPDATE|DELETE|DROP|USE)\b", upper):
            return self._err()

        # USE database
        if upper.startswith('USE '):
            db = s.split(None, 1)[1]
            state['current_db'] = db
            if self.use_ollama:
                return self._ollama_render(cmd, state, mutation_applied=True, default=self._ok('Database changed'))
            return self._ok('Database changed')

        # SHOW TABLES
        if upper == 'SHOW TABLES':
            tables = sorted(state['schemas'].keys())
            rows = [[t] for t in tables]
            out = self._render_table(['Tables_in_' + state['current_db']], rows)
            default = f"{out}\n{self._prompt()}"
            if self.use_ollama:
                return self._ollama_render(cmd, state, table_headers=['Tables_in_' + state['current_db']], table_rows=rows, default=default)
            return default

        # DESCRIBE / DESC table
        m = re.match(r"^(DESCRIBE|DESC)\s+([a-zA-Z_][a-zA-Z0-9_]*)$", upper)
        if m:
            table = s.split()[1]
            if table not in state['schemas']:
                return self._err()
            cols = state['schemas'][table]
            rows = [[c, 'varchar(255)', 'YES', 'MUL', None, ''] for c in cols]
            out = self._render_table(['Field', 'Type', 'Null', 'Key', 'Default', 'Extra'], rows)
            default = f"{out}\n{self._prompt()}"
            if self.use_ollama:
                return self._ollama_render(cmd, state, table_headers=['Field','Type','Null','Key','Default','Extra'], table_rows=rows, default=default)
            return default

        # CREATE TABLE name (col ...)
        m = re.match(r"^CREATE\s+TABLE\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\((.+)\)$", s, re.IGNORECASE)
        if m:
            name = m.group(1)
            if name in state['schemas']:
                if self.use_ollama:
                    return self._ollama_render(cmd, state, mutation_applied=True, default=self._ok('Query OK, 0 rows affected'))
                return self._ok('Query OK, 0 rows affected')
            cols_raw = m.group(2)
            cols = [re.split(r"\s+", c.strip())[0] for c in cols_raw.split(',') if c.strip()]
            if not cols:
                return self._err()
            state['schemas'][name] = cols
            state['rows'][name] = []
            if self.use_ollama:
                return self._ollama_render(cmd, state, mutation_applied=True, default=self._ok('Query OK, 0 rows affected'))
            return self._ok('Query OK, 0 rows affected')

        # INSERT INTO table VALUES (...)
        m = re.match(r"^INSERT\s+INTO\s+([a-zA-Z_][a-zA-Z0-9_]*)\s+VALUES\s*\((.*)\)$", s, re.IGNORECASE)
        if m:
            table = m.group(1)
            if table not in state['schemas']:
                return self._err()
            values = [v.strip().strip("'\"") for v in re.split(r",(?=(?:[^']*'[^']*')*[^']*$)", m.group(2))]
            state['rows'][table].append(values)
            if self.use_ollama:
                return self._ollama_render(cmd, state, mutation_applied=True, default=self._ok('Query OK, 1 row affected'))
            return self._ok('Query OK, 1 row affected')

        # SELECT * FROM table
        m = re.match(r"^SELECT\s+\*\s+FROM\s+([a-zA-Z_][a-zA-Z0-9_]*)$", upper)
        if m:
            table = s.split()[-1]
            if table not in state['schemas']:
                return self._err()
            headers = state['schemas'][table]
            out = self._render_table(headers, state['rows'][table])
            default = f"{out}\n{self._prompt()}"
            if self.use_ollama:
                return self._ollama_render(cmd, state, table_headers=headers, table_rows=state['rows'][table], default=default)
            return default

        # DROP TABLE name
        m = re.match(r"^DROP\s+TABLE\s+([a-zA-Z_][a-zA-Z0-9_]*)$", upper)
        if m:
            table = s.split()[-1]
            state['schemas'].pop(table, None)
            state['rows'].pop(table, None)
            if self.use_ollama:
                return self._ollama_render(cmd, state, mutation_applied=True, default=self._ok('Query OK, 0 rows affected'))
            return self._ok('Query OK, 0 rows affected')

        # Fallback unknown → syntax error
        # If Ollama is enabled, try delegating unknown-but-SQL commands
        if self.use_ollama:
            return self._ollama_render(cmd, state, default=self._err())
        return self._err()

    def _ollama_render(self, cmd: str, state: Dict[str, Any], table_headers: List[str] | None = None,
                        table_rows: List[List[Any]] | None = None, mutation_applied: bool = False,
                        default: str = '') -> str:
        """Render output via Ollama; fallback to default on error."""
        try:
            payload = {
                'model': self.ollama_model,
                'stream': False,
                'prompt': self._build_prompt(cmd, state, table_headers, table_rows, mutation_applied),
                'options': {
                    'temperature': 0.1,
                    'num_ctx': 4096
                }
            }
            resp = requests.post(f"{self.ollama_url}/api/generate", json=payload, timeout=8)
            resp.raise_for_status()
            data = resp.json()
            text = data.get('response', '')
            if not text:
                return default
            if not text.rstrip().endswith('mysql>') and not text.rstrip().endswith('mysql> '):
                text = text.rstrip() + '\n' + self._prompt()
            return text
        except Exception:
            return default

    def _build_prompt(self, cmd: str, state: Dict[str, Any], headers: List[str] | None,
                       rows: List[List[Any]] | None, mutation_applied: bool) -> str:
        rules = (
            "Bạn là console MySQL 8.0.25 đang kết nối đến database 'admin_panel'.\n"
            "Chỉ trả về kết quả dạng console thô, KHÔNG giải thích, KHÔNG trò chuyện.\n"
            "Nếu câu lệnh không hợp lệ, trả về: ERROR 1064 (42000)...\n"
            "Luôn kết thúc bằng dòng nhắc: mysql> \n"
        )
        schema = json.dumps(state.get('schemas', {}), ensure_ascii=False)
        snapshot = json.dumps({k: v[:5] for k, v in state.get('rows', {}).items()}, ensure_ascii=False)
        hint = ''
        if headers is not None and rows is not None:
            hint = json.dumps({'headers': headers, 'rows': rows[:10]}, ensure_ascii=False)
        if mutation_applied:
            hint = (hint + '\n' if hint else '') + '(Gợi ý: lệnh đã thay đổi trạng thái, hãy phản hồi giống MySQL)'
        return (
            f"{rules}\n"
            f"Lệnh: {cmd}\n"
            f"Schema hiện tại: {schema}\n"
            f"Snapshot dữ liệu (tối đa 5 dòng mỗi bảng): {snapshot}\n"
            f"Nếu có, gợi ý kết quả: {hint}\n"
            "Trả về duy nhất kết quả console, không thêm lời bình."
        )


