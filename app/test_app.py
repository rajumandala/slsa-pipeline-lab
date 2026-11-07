from app.app import app


def test_hello():
    resp = app.test_client().get("/hello")
    assert resp.status_code == 200
    assert resp.get_json() == {"message": "hello"}
