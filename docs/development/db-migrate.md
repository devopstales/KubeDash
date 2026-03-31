### flask db migrate

Uses Flask-Migrate (Alembic). The repo has a `migrations` folder and `alembic.ini`.

**Plugin models:** All plugins that have a `model.py` or `models.py` under `plugins/<name>/` are discovered from the filesystem and loaded into `db.metadata` when running migrations. Alembic autogenerate therefore sees those tables (e.g. `ai_chat_conversations`, `ai_chat_messages` for the ai_chat plugin), so `flask db migrate -m "add: ai-chat models"` will generate migrations for new or changed plugin tables. Plugin enable/disable in config does not affect migration discovery.

```bash
export FLASK_APP=kubedash
flask db init

flask db migrate -m "users table"
flask db upgrade

flask db migrate -m "posts table"
flask db upgrade

flask db history

flask db downgrade
```
