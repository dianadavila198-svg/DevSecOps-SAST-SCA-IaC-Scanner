# UoA Sensory Map

**UoA Sensory Map** is an interactive web platform for the University of Aberdeen that
helps neurodivergent students and visitors navigate campus using sensory-aware mapping.
It visualises noise, lighting, temperature, scents, crowd levels and quiet zones, and
supports user feedback and accessible wayfinding.

Inspired by the [TCD Sense Map](https://tcdsensemap.ie/).

---

## Features

- Interactive **map** and **list** of campus locations.
- **Sensory profiles** for each location across five axes: Auditory, Visual,
  Olfactory, Thermal and Vestibular (rated 1–5).
- **Filtering** by category and by sensory level (e.g. low noise).
- **Quiet zones** highlighted for low-stimulation spaces.
- **Search and sort** locations.
- **User reports** of current conditions, with **admin moderation**.
- **Facilities** info (wheelchair access, WiFi, power, etc.).
- **Sensory radar chart** and **mobile-friendly**, accessible UI.

## Tech Stack

- **Backend:** Django (Python) + Django REST Framework
- **Frontend:** HTML / CSS / vanilla JavaScript (no build step); map & charts via CDN
- **Database:** SQLite (development)
- **Testing:** Django test framework

## Requirements

- Python 3.12
- pip and venv

## Getting Started

1. **Clone the repository**

   ```bash
   git clone https://github.com/FaizanKhan-AutoDev/UoASensoryMap.git
   cd UoASensoryMap
   ```
2. **Create and activate a virtual environment**

   ```powershell
   py -m venv .venv
   .\.venv\Scripts\Activate.ps1     # Windows PowerShell
   # source .venv/bin/activate      # macOS / Linux
   ```
3. **Install dependencies**

   ```bash
   pip install -r requirements.txt
   ```
4. **Apply database migrations**

   ```bash
   python manage.py migrate
   ```
5. **Run the development server**

   ```bash
   python manage.py runserver
   ```

   Open http://127.0.0.1:8000/ in your browser.
6. **(Optional) Create an admin user**

   ```bash
   python manage.py createsuperuser
   ```

   Then visit http://127.0.0.1:8000/admin/.

## Running Tests

```bash
python manage.py test
```

## API

Locations are available at:

```text
GET /api/locations/
POST /api/locations/
GET /api/locations/<id>/
PUT /api/locations/<id>/
DELETE /api/locations/<id>/
```

The location list supports simple filters:

```text
/api/locations/?category=quiet
/api/locations/?axis=auditory&max_level=2
/api/locations/?axis=visual&min_level=3
```

Valid sensory axes are `auditory`, `visual`, `olfactory`, `thermal`, and
`vestibular`.

## Project Documentation

- Team charter: `docs/team_charter.md`
- Database schema: `docs/database_schema.md`
- Report starter notes: `docs/report_drafts.md`

## Project Structure

```
UoASensoryMap/
├─ manage.py
├─ requirements.txt
├─ UoASensoryMap/        # project configuration (settings, urls, wsgi)
└─ sensemap/             # main app (models, views, serializers, templates, static)
```

## Contributing

This is a university group project. Before writing code, read the team coding
guidelines and follow the branch-and-pull-request workflow:

- Create a feature branch: `git checkout -b feature/<task>`
- Commit in small, logical chunks with clear messages.
- Open a Pull Request for review before merging to `main`.
- Never commit `.venv/`, `db.sqlite3`, or secrets.

## Team Bravo

University of Aberdeen — group project (2026).

## License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file
for details.
