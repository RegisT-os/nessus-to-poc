"""Recipe library loading.

Recipes are declarative YAML. The built-in library ships **inside the package**
(``vapt_verify/recipes/data/*.yaml``) and is located with
:mod:`importlib.resources`, so it resolves correctly for every install layout:
editable installs, ordinary ``pip install`` into ``site-packages``, virtualenvs,
zipapps and Windows ``Scripts\\`` entry points alike.

Historically the loader resolved the library by walking up from ``__file__`` to
a repository-relative ``recipes/`` directory. That only worked from a source
checkout: a normal ``pip install`` shipped no recipes at all, so every
classification crashed with "manual-review-fallback recipe is missing". The
package-data lookup below is the fix; ``VAPT_VERIFY_RECIPES_DIR`` and profile
directories can still add or override recipes.

Nothing here executes recipe content — YAML is parsed with ``yaml.safe_load``.
"""

from __future__ import annotations

import os
from importlib import resources
from pathlib import Path

import yaml

from vapt_verify.models.recipe import Recipe

_PACKAGE_DATA = "vapt_verify.recipes.data"
# Optional operator override, e.g. a site-wide recipe directory.
_ENV_OVERRIDE = "VAPT_VERIFY_RECIPES_DIR"


class RecipeLibraryError(RuntimeError):
    """Raised when the built-in recipe library cannot be loaded."""


class RecipeLibrary:
    """An ordered collection of recipes, sorted by selection layer."""

    def __init__(self, recipes: list[Recipe]) -> None:
        # Sort by selection layer so more specific recipes are considered first.
        self._recipes = sorted(recipes, key=lambda r: r.selection_layer.value)

    def __len__(self) -> int:
        return len(self._recipes)

    @property
    def recipes(self) -> list[Recipe]:
        return list(self._recipes)

    def by_id(self, recipe_id: str) -> Recipe | None:
        for recipe in self._recipes:
            if recipe.recipe_id == recipe_id:
                return recipe
        return None

    # -- loading ------------------------------------------------------------

    @classmethod
    def load_builtin(cls) -> RecipeLibrary:
        """Load the packaged library, plus any ``VAPT_VERIFY_RECIPES_DIR`` overrides.

        Raises :class:`RecipeLibraryError` with actionable guidance if the
        packaged data is missing or unreadable, rather than failing later with an
        obscure "fallback recipe is missing" error.
        """
        recipes: dict[str, Recipe] = {}
        for recipe in cls._load_package_data():
            recipes[recipe.recipe_id] = recipe

        override = os.environ.get(_ENV_OVERRIDE, "").strip()
        if override:
            for recipe in cls._load_dir(Path(override)):
                recipes[recipe.recipe_id] = recipe

        if not recipes:
            raise RecipeLibraryError(
                "No verification recipes could be loaded. The packaged recipe library "
                f"('{_PACKAGE_DATA}') appears to be missing from this installation. "
                "Reinstall the package (pip install --force-reinstall vapt-verify), or "
                f"point {_ENV_OVERRIDE} at a directory of recipe YAML files."
            )
        return cls(list(recipes.values()))

    @classmethod
    def load_dirs(cls, dirs: list[Path]) -> RecipeLibrary:
        """Load recipes from explicit directories only (used by tests/profiles)."""
        recipes: dict[str, Recipe] = {}
        for directory in dirs:
            for recipe in cls._load_dir(directory):
                # Later directories override earlier ones by recipe_id.
                recipes[recipe.recipe_id] = recipe
        return cls(list(recipes.values()))

    def with_overrides(self, directory: str | Path) -> RecipeLibrary:
        """Return a new library with ``directory``'s recipes layered on top."""
        merged = {r.recipe_id: r for r in self._recipes}
        for recipe in self._load_dir(Path(directory)):
            merged[recipe.recipe_id] = recipe
        return RecipeLibrary(list(merged.values()))

    # -- sources ------------------------------------------------------------

    @staticmethod
    def _load_package_data() -> list[Recipe]:
        recipes: list[Recipe] = []
        try:
            anchor = resources.files(_PACKAGE_DATA)
        except (ModuleNotFoundError, TypeError):  # pragma: no cover - defensive
            return recipes
        for entry in sorted(anchor.iterdir(), key=lambda p: p.name):
            if not entry.name.endswith((".yaml", ".yml")):
                continue
            try:
                text = entry.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):  # pragma: no cover - defensive
                continue
            recipes.extend(RecipeLibrary._parse(text, source=entry.name))
        return recipes

    @staticmethod
    def _load_dir(directory: Path) -> list[Recipe]:
        recipes: list[Recipe] = []
        if not directory.exists():
            return recipes
        for path in sorted(directory.glob("*.y*ml")):
            recipes.extend(
                RecipeLibrary._parse(path.read_text(encoding="utf-8"), source=str(path))
            )
        return recipes

    @staticmethod
    def _parse(text: str, *, source: str) -> list[Recipe]:
        try:
            data = yaml.safe_load(text) or {}
        except yaml.YAMLError as exc:
            raise RecipeLibraryError(f"invalid recipe YAML in {source}: {exc}") from exc
        raw_recipes = data.get("recipes", []) if isinstance(data, dict) else []
        return [Recipe.from_dict(item) for item in raw_recipes]

    # -- diagnostics --------------------------------------------------------

    @staticmethod
    def builtin_location() -> str:
        """Human-readable location of the packaged library (for ``doctor``)."""
        try:
            return str(resources.files(_PACKAGE_DATA))
        except (ModuleNotFoundError, TypeError):  # pragma: no cover - defensive
            return "(not found)"
