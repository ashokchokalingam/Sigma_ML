from app import create_app

app = create_app()

if __name__ == '__main__':
    app.run(host='172.16.0.75', port=5000, debug=True)
