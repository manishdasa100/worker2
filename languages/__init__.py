"""
Language registry. To add a language: implement BaseLanguage, register it here.
"""
from languages.c import CLanguage
from languages.cpp import CppLanguage
from languages.go import GoLanguage
from languages.java import JavaLanguage
from languages.python import PythonLanguage

LANGUAGES = {
    "python": PythonLanguage(),
    "java": JavaLanguage(),
    "cpp": CppLanguage(),
    "c": CLanguage(),
    "go": GoLanguage(),
}


def get_language(name: str):
    """Handler for `name`, or None if unregistered."""
    return LANGUAGES.get(name.lower())
