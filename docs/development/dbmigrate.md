
### flask db migrate

It use Flask-Migrate that use alembic. In the source repo creates a `migrations` repo with the `alembic.ini` config

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
