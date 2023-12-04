import re
import hashlib
import json
import random
import string

def verifier_mot_de_passe(mot_de_passe):
    if len(mot_de_passe) < 8:
        return "Le mot de passe doit contenir au moins 8 caractères."
    elif not re.search("[a-z]", mot_de_passe):
        return "Le mot de passe doit contenir au moins une lettre minuscule."
    elif not re.search("[A-Z]", mot_de_passe):
        return "Le mot de passe doit contenir au moins une lettre majuscule."
    elif not re.search("[0-9]", mot_de_passe):
        return "Le mot de passe doit contenir au moins un chiffre."
    elif not re.search("[!@#$%^&*]", mot_de_passe):
        return "Le mot de passe doit contenir au moins un caractère spécial (!, @, #, $, %, ^, &, *)."
    else:
        return "Le mot de passe est sécurisé."

def ajouter_mot_de_passe(nom, mot_de_passe):
    with open('mots_de_passe.json', 'r+') as f:
        data = json.load(f)
        hashed_password = hashlib.sha256(mot_de_passe.encode()).hexdigest()
        if hashed_password in data.values():
            return "Ce mot de passe existe déjà."
        data[nom] = hashed_password
        f.seek(0)
        json.dump(data, f)
        return "Le mot de passe a été ajouté avec succès."

def afficher_mots_de_passe():
    with open('mots_de_passe.json', 'r') as f:
        data = json.load(f)
        for nom, mot_de_passe in data.items():
            print(f'Nom: {nom}, Mot de passe haché: {mot_de_passe}')

def generer_mot_de_passe():
    length = 10
    password_characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(password_characters) for i in range(length))
    return password

with open('mots_de_passe.json', 'w') as f:
    json.dump({}, f)

while True:
    mot_de_passe = input("Veuillez choisir un mot de passe ou tapez 'g' pour générer un mot de passe aléatoire: ")
    if mot_de_passe.lower() == 'g':
        mot_de_passe = generer_mot_de_passe()
        print("Votre mot de passe généré est : " + mot_de_passe)
    resultat = verifier_mot_de_passe(mot_de_passe)
    print(resultat)
    if resultat == "Le mot de passe est sécurisé.":
        nom = input("Veuillez entrer un nom pour ce mot de passe: ")
        resultat = ajouter_mot_de_passe(nom, mot_de_passe)
        print(resultat)
        if resultat == "Le mot de passe a été ajouté avec succès.":
            break

afficher_mots_de_passe()