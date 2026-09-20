"""Boring app code. The agent has a legitimate reason to be in this repo."""
import os


def load():
    return {
        "env": os.getenv("APP_ENV", "dev"),
        "db": os.getenv("DATABASE_URL"),
    }
