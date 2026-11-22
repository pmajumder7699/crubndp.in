from app import create_app
app = create_app()

if __name__ == "__main__":
    # Local development only. For internet deployment use a production WSGI server
    # behind HTTPS, e.g. gunicorn, and set COOKIE_SECURE=true.
    app.run(host="127.0.0.1", port=5000, debug=False)
