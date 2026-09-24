from functools import wraps

from flask import (
session,
redirect,
url_for,
flash
)

def login_required(function):

@wraps(function)
def wrapper(*args, **kwargs):

    if "user_id" not in session:

        flash(
            "Please log in first.",
            "error"
        )

        return redirect(
            url_for("login")
        )

    return function(*args, **kwargs)

return wrapper

def admin_required(function):

@wraps(function)
def wrapper(*args, **kwargs):

    if "user_id" not in session:

        return redirect(
            url_for("login")
        )

    if session.get("role") != "admin":

        flash(
            "Administrator access required.",
            "error"
        )

        return redirect(
            url_for("index")
        )

    return function(*args, **kwargs)

return wrapper
