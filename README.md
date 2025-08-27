# 🔐 Flask Auth (Local + Google OAuth)

## 🎯 But du projet  
Ce projet a pour but de **mettre en place un vrai site web relié à un serveur Flask**, permettant de gérer l’authentification des utilisateurs :  
- Les visiteurs peuvent **s’inscrire** avec un e-mail/mot de passe ou via **Google** (OAuth2).  
- Après connexion, l’utilisateur accède à une **page protégée** confirmant son inscription/connexion.  
- Les comptes et informations sont stockés dans une base de données **SQLite**, ce qui en fait une base solide pour déployer un **site web fonctionnel avec serveur backend**.  

---

## ⚙️ Fonctionnalités principales  
✅ Inscription locale sécurisée avec règles de mot de passe strictes  
✅ Connexion avec mot de passe hashé (Werkzeug)  
✅ Authentification externe via **Google Sign-In (OAuth2)**  
✅ Gestion de session utilisateur (login/logout)  
✅ Page profil protégée (`/profile`)  
✅ Vue admin listant les utilisateurs (`/admin/users`)  

---

## 🛠️ Stack technique  
- **Backend / Serveur** : Flask, SQLite, Authlib (Google OAuth), Werkzeug Security  
- **Frontend** : HTML/CSS responsive avec UI moderne et animations  
- **Base de données** : SQLite (`app.db`)  
---


   
