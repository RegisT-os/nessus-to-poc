"""Recipe library loading.

Recipes are loaded from declarative YAML files. The built-in library ships with
the package (``recipes/builtin.yaml`` at the repository root); a profile may add
or override recipes from its own directory (task section 13). Nothing here
executes recipe content — YAML is parsed with ``yaml.safe_load``.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from vapt_verify.models.recipe import Recipe

# The built-in library lives at <repo-root>/recipes/builtin.yaml. From this file
# (src/vapt_verify/recipes/library.py) that is three parents up + "recipes".
_BUILTIN_DIR = Path(__file__).resolve().parents[3] / "recipes"


class RecipeLibrary:
    """An ordered collection of recipes, sorted by selection layer."""

    def __init__(self, recipes: list[Recipe]) -> None:
        # Sort by selection layer so more specific recipes are considered first.
        self._recipes = sorted(recipes, key=lambda r: r.selection_layer.value)

    @property
    def recipes(self) -> list[Recipe]:
        return list(self._recipes)

    def by_id(self, recipe_id: str) -> Recipe | None:
        for recipe in self._recipes:
            if recipe.recipe_id == recipe_id:
                return recipe
        return None

    @classmethod
    def load_builtin(cls) -> RecipeLibrary:
        return cls.load_dirs([_BUILTIN_DIR])

    @classmethod
    def load_dirs(cls, dirs: list[Path]) -> RecipeLibrary:
        recipes: dict[str, Recipe] = {}
        for directory in dirs:
            if not directory.exists():
                continue
            for path in sorted(directory.glob("*.yaml")):
                for recipe in cls._load_file(path):
                    # Later directories override earlier ones by recipe_id.
                    recipes[recipe.recipe_id] = recipe
        return cls(list(recipes.values()))

    @staticmethod
    def _load_file(path: Path) -> list[Recipe]:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        raw_recipes = data.get("recipes", []) if isinstance(data, dict) else []
        return [Recipe.from_dict(item) for item in raw_recipes]
