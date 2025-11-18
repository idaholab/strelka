from __future__ import annotations

# define these early so that the plugin support can use them
__namespace__ = "com.target.strelka"
__version__ = "0.0.0"

# do this early, since this should, in theory, be loaded pretty quickly in the
# overall execution of anything using Strelka; because we can call the registrar
# multiple times, we also can go ahead and force early plugin paths from our
# environment, which should help us with pytest/testcases, etc.
from .plugins import register_env_plugin_paths

register_env_plugin_paths()
