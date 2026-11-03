"""
Language registry. To add a language: implement BaseLanguage, register it here.
"""
from languages.cpp import CppLanguage
from languages.java import JavaLanguage
from languages.python import PythonLanguage

LANGUAGES = {
    "python": PythonLanguage(),
    "java": JavaLanguage(),
    "cpp": CppLanguage(),
}


def get_language(name: str):
    """Handler for `name`, or None if unregistered."""
    return LANGUAGES.get(name.lower())
