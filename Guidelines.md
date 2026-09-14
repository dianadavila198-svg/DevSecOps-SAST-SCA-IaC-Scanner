# Contributing & Coding Guidelines — UoA Sensory Map

Everyone on the team must read this before writing code. These rules keep our
codebase clean, consistent, and easy for 7 people to work on at once.

> **Golden rule:** Leave every file better (or at least no worse) than you found it.
> If you touch a file, you are responsible for it still working when you push.

---

## 1. Before You Start Coding (every time)

1. Make sure your virtual environment is active — your prompt must show `(.venv)`.

   ```powershell
   .\.venv\Scripts\Activate.ps1
   ```
2. Get the latest `main` before branching:

   ```powershell
   git checkout main
   git pull
   ```
3. Install any new dependencies:

   ```powershell
   pip install -r requirements.txt
   ```
4. Create a **new branch** for your task (never commit straight to `main`):

   ```powershell
   git checkout -b feature/<short-task-name>
   ```

   Examples: `feature/location-model`, `fix/map-pin-color`, `test/report-api`.

---

## 2. Branching & Commits

- **One branch per task.** Keep branches small and focused.
- **Branch naming:** `feature/...`, `fix/...`, `test/...`, `docs/...`.
- **Never push directly to `main`.** Open a Pull Request and get one review.
- **Commit messages:** short imperative subject (max ~50 chars), optional body.
  ```
  Add Location model and API endpoint

  - Add Location model with lat/lng and category
  - Register LocationViewSet on /api/locations/
  ```
- **Do NOT** paste the whole `git commit -m "..."` command as the message.
- Commit **often**, in logical chunks. Don't bundle 10 unrelated changes.
- **Pull `main` into your branch regularly** to avoid huge merge conflicts.

---

## 3. What NEVER to Commit

These are in `.gitignore` — keep them there:

- `.venv/` — your local virtual environment.
- `db.sqlite3` — the local database (everyone has their own).
- `__pycache__/`, `*.pyc` — compiled Python.
- `.env` — secrets and local settings.

**Never commit:**

- Secrets, API keys, passwords, or the production `SECRET_KEY`.
- Large binary files or screenshots (link them in the report instead).
- Commented-out blocks of dead code — delete them; Git remembers history.

---

## 4. Project Structure — Where Things Go

Put new code in the right place so others can find it.

| You are adding...           | Put it in...                                    |
| --------------------------- | ----------------------------------------------- |
| A database table            | `sensemap/models.py`                          |
| JSON conversion for the API | `sensemap/serializers.py`                     |
| An API endpoint / page view | `sensemap/views.py`                           |
| A URL route                 | `sensemap/urls.py`                            |
| Admin/moderation config     | `sensemap/admin.py`                           |
| Sample data                 | `sensemap/management/commands/seed.py`        |
| An HTML page                | `sensemap/templates/sensemap/`                |
| CSS                         | `sensemap/static/sensemap/css/`               |
| JavaScript                  | `sensemap/static/sensemap/js/`                |
| A test                      | `sensemap/tests.py` (or a `tests/` package) |
| A new dependency            | `requirements.txt` (pin the version!)         |

- **Do not** put business logic in `settings.py` or `urls.py`.
- **Do not** create new top-level folders without asking the team.

---

## 5. Python / Django Style

- Follow **PEP 8** (4-space indentation, `snake_case` for functions/variables,
  `PascalCase` for classes).
- Keep lines under ~100 characters.
- **Imports at the top of the file only**, grouped: standard library, third-party,
  then local app imports.
- Model classes are singular and `PascalCase`: `Location`, `SensoryProfile`.
- Give models a `__str__` method so they read well in the admin.
- **Always create migrations** when you change a model, and commit them:
  ```powershell
  python manage.py makemigrations
  python manage.py migrate
  ```
- Never edit a migration that has already been pushed — make a new one.
- Use Django's ORM, not raw SQL, unless absolutely necessary.

---

## 6. API (Django REST Framework) Rules

- Endpoints live under `/api/` and return JSON.
- Use **serializers** for all input/output — never build JSON by hand.
- Validate user input in the serializer, not the view.
- Keep URLs lowercase and plural: `/api/locations/`, `/api/reports/`.
- Don't break an existing endpoint's response shape without telling the team
  (the frontend depends on it).

---

## 7. Frontend (HTML / CSS / JS) Rules

- **No frameworks/build step** — plain HTML, CSS and vanilla JavaScript only
  (libraries via CDN are fine, e.g. MapLibre, Chart.js).
- Extend `base.html`; don't duplicate the header/nav.
- Keep CSS in `style.css`; use clear class names (`.location-card`, not `.lc1`).
- JS: use `const`/`let` (never `var`), and `fetch()` for API calls.
- Always include the **CSRF token** on POST requests.
- **Accessibility matters** (this is a sensory app):
  - Every interactive element must be keyboard reachable.
  - Add `alt` text / `aria-label`s to icons and images.
  - Don't rely on colour alone to convey meaning.

---

## 8. Comments & Documentation

- Write code that explains itself with good names first.
- Add a comment to explain **why**, not **what**, when something is non-obvious.
- Update the `README.md` if you change how to set up or run the project.
- If you add a feature, note it for the team so the report stays accurate.

---

## 9. Testing — Definition of Done

A task is **not done** until:

- [ ] The code works locally (`python manage.py runserver` with no errors).
- [ ] `python manage.py check` passes.
- [ ] There is **at least one test** for new logic (happy + unhappy path).
- [ ] All tests pass: `python manage.py test`.
- [ ] A teammate has **reviewed and approved** your Pull Request.
- [ ] It is merged to `main` and still works there.

Never merge a branch with failing tests or that breaks `main`.

---

## 10. Pull Request Checklist

Before you request a review, confirm:

- [ ] Branched from an up-to-date `main`.
- [ ] Only relevant files are changed (no `db.sqlite3`, no `.venv/`).
- [ ] Migrations are included if models changed.
- [ ] Tests added and passing.
- [ ] Commit messages are clear.
- [ ] You wrote a short PR description of *what* and *why*.

---

## 11. When You Get Stuck

- Try for **30–60 minutes**, then **ask the team** — don't sit blocked for hours.
- Don't force-push to shared branches (`main`) without agreement.
- If you break something on `main`, tell the team immediately so we can fix it
  together.
