from blinker import signal

on_login = signal("on_login")
on_logout = signal("on_logout")


__all__ = ["on_login", "on_logout"]