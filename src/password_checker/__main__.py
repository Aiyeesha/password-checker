"""
Permet de lancer l'outil avec « python -m password_checker ».
Utile si la commande « password-checker » n'est pas dans le PATH.
"""

from password_checker.cli import main

# SystemExit transmet le code de retour de main() au système d'exploitation
raise SystemExit(main())
