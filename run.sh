#!/bin/bash

export PYTHONPATH="src:$PYTHONPATH"
export DJANGO_SETTINGS_MODULE="test_settings"

usage() {
    echo "USAGE: $0 [command]"
    echo "  test - run the tests"
    echo "  shell - open the Django shell"
    echo "  check - run ruff linter and formatter"
    echo "  fmt - format code with ruff"
    echo "  lint - run ruff linter only"
    exit 1
}

case "$1" in
    "test" )
        uv run django-admin test multidb ;;
    "shell" )
        uv run django-admin shell ;;
    "check" )
        uv run ruff check src/ && uv run ruff format --check src/ ;;
    "fmt" )
        uv run ruff format src/ ;;
    "lint" )
        uv run ruff check src/ ;;
    * )
        usage ;;
esac
