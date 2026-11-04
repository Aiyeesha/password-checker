# Politique de sécurité

## Versions prises en charge

| Version | Prise en charge |
|---------|-----------------|
| 1.x     | ✅ |
| < 1.0   | ❌ |

## Signaler une vulnérabilité

Merci de **ne pas ouvrir d'issue publique** pour une faille de sécurité.

Utilisez le signalement privé de GitHub :
onglet **Security** du dépôt → **Report a vulnerability**.

Indiquez si possible :
- la version concernée (`password-checker --version`) ;
- une description du problème et de son impact ;
- les étapes permettant de le reproduire.

⚠️ **N'incluez jamais un vrai mot de passe** dans un signalement : utilisez un exemple fictif.

## Délais

Il s'agit d'un projet personnel maintenu sur le temps libre : chaque signalement est lu et
traité au mieux, avec un accusé de réception visé sous 7 jours.

## Périmètre

Sont notamment concernés : toute fuite du mot de passe (affichage, journalisation, transmission),
tout envoi au réseau d'autre chose que le préfixe de 5 caractères, et toute faiblesse dans le
traitement de la réponse de l'API.
