
# Evil Plant
D'après nos analyses couplées à nos relevés satellites, nous avons confirmation que la cible, sous couverture d'être une usine de production de vaccins, est en réalité une usine de production de liquide toxique utilisée à des fins militaires.

Les reconnaissances du réseau effectuées nous indiquent que la cible est contrôlée par un automate programmable industriel, lui-même communiquant via une interface SCADA par le protocole OPC-UA en mode binaire. Nous avons exposé la cible sur internet via un implant UMTS, celle-ci est désormais accessible sur le réseau :
        
        evil-plant.france-cybersecurity-challenge.fr:4841

Un screenshot de l'interface SCADA à un temps indéterminé a également pu être récupéré :




![App Screenshot](https://france-cybersecurity-challenge.fr/files/9b37798c50edb8084c3fabb6129071c5/evil-plant.png)


L'analyse des documents d'ingénierie récupérés a montré que la formule du liquide toxique est composée de 16 éléments. Nous ignorons les taux utilisés dans la formule ainsi que l'ordonnancement des différents éléments : nous faisons appel à vous pour les récupérer.

Il semblerait que les éléments soient ajoutés dans la cuve MIX (en bas du screenshot) deux par deux, mais pour pouvoir créer un remède efficace, nous avons besoin de savoir exactement dans quel ordre et avec quels taux les couples d'éléments sont mélangés.

Faites vite, le temps presse...

Note : Le numéro des éléments dans un couple d'éléments est à indiquer dans l'ordre croissant (030c et pas 0c03 dans l'étape 2 de l'exemple ci-dessous), et les taux correspondants dans le même ordre.

Exemple : On donne un exemple du format du flag à soumettre. Supposons que le processus de fabrication comporte les trois étapes suivantes :

Étape 1 : ajout de 27 unités (0x1b) de l'élément 1 (0x01) et de 47 unités (0x2f) de l'élément 8 (0x08) dans la cuve MIX.

Étape 2 : ajout de 95 unités (0x5f) de l'élément 12 (0x0c) et de 141 unités (0x8d) de l'élément 3 (0x03) dans la cuve MIX.

Étape 3 : ajout de 230 unités (0xe6) de l'élément 5 (0x05) et de 177 unités (0xb1) de l'élément 16 (0x10) dans la cuve MIX.

Le flag à soumettre serait FCSC{01081b2f030c8d5f0510e6b1}, où toutes les valeurs sont exprimées en notation hexadécimale.



## Etape 1 :  Qu'est ce qu'une interface SCADA ?
    
    Une interface SCADA (Supervisory Control and Data Acquisition)
    est un système utilisé pour surveiller et contrôler des processus 
    industriels, tels que la production, la distribution et le
    traitement de l'énergie, de l'eau et des déchets. Les interfaces SCADA
    sont généralement composées d'un logiciel central qui communique avec
    des dispositifs de terrain, tels que des capteurs, des actionneurs 
    et des contrôleurs logiques programmables (PLC),
    pour surveiller et contrôler les processus en temps réel.


## Etape 2 - Creation d'un script pour se connecter à l'usine et collecter des informations  

        from opcua import Client
        url = "opc.tcp://evil-plant.france-cybersecurity-challengefr:4841"
        client = Client(url)

        try:
            client.connect()
            # Interagir avec l'interface SCADA ici
            root = client.get_root_node()
            for child in root.get_children():
                print(child)
            # Récupérer les informations sur les éléments et les taux
        finally:
            client.disconnect()


![App screenshot](https://cdn.discordapp.com/attachments/952706654464512030/1102312181615308920/image.png)

on remarque que la racine possède 3 noeuds, on va alors essayer d'avoir plus d'informations sur ces noeuds.

![App screenshot](https://cdn.discordapp.com/attachments/952706654464512030/1102313130178129991/image.png)

on a alors comme résultat : 

![App screenshot](https://cdn.discordapp.com/attachments/952706654464512030/1102313222415069394/image.png)


on comprend alors que ce qui nous interesse c'est le premier noeud de la racine et ses enfants car ceux-ci contiennent les vanves et les contenants ainsi que le mix.
## Etape 3 - Observer les activités des vanves et collecter le dosage

Après m'etre documenté sur opcua en pyton, j'ai découvert qu'il existe des variable et qu'on peut peut utiliser une fonction et souscrire à un système d'alert pour connaçitre les changements qu'il y'a eu 

j'ai donc modifié mon script 

        

    lis = []
    class DataChangeHandler(object):
    def __init__(self):
        self.last_values = {}
        self.flag = [] 

    def datachange_notification(self, node, val, data):
        print("Changement de données détecté pour le nœud :", node)
        very_old = 0
        if node in self.last_values:
            old_val = self.last_values[node]
            print("Ancienne valeur :", old_val)
            very_old = old_val
        else:
            old_val = None
        print("Nouvelle valeur :", val)
        self.last_values[node] = val
        if str(node).split(";i")[1][1:].isnumeric() == True  and str(node) != "ns=1;i=6050":
            if( very_old - val >  0 and very_old - val < 10000 and 6011 <= int(str(node).split(";i")[1][1:]) <= 6026 ): 
                lis.append([very_old - val, str(node).split(";i")[1][1:]])
        if node in self.last_values:
            print( "réduction =",  very_old - val  )
        if( len(lis) == 8):
            self.flag = lis

    url = "opc.tcp://evil-plant.france-cybersecurity-challenge.fr:4841"
    client = Client(url)
    client.connect()
    # Créez des souscriptions pour surveiller les changements de valeurs des vannes et de la cuve MIX
    sub = client.create_subscription(500, DataChangeHandler())

    interval = [i for i in range(11, 27) ] + [ j for j in range(31, 47)] 
    valve_nodes = [client.get_node(f"ns=1;i=60{i}") for i in interval ]
    mix_node = client.get_node("ns=1;i=6050")

    mix_element = client.get_node("ns=1;i=6051")

    handles = [sub.subscribe_data_change(node) for node in valve_nodes + [mix_node] + [mix_element] ]

    # Attendez que les changements de valeurs soient détectés et enregistrés
    input("Appuyez sur Entrée pour arrêter la surveillance...")

    # Supprimez les souscriptions
    for handle in handles:
        sub.unsubscribe(handle)

    client.disconnect()
    print(lis)

En utilisant le script, on remarque que les valeur changent de manière constante, et la valeur du MIX passe de 0 à 2505 puis reviens à 0. J'ai donc lancé une surveillance puis à quelques instants après, j'ai une liste de tous les changements 

![App screenshot](https://media.discordapp.net/attachments/952706654464512030/1102317136279515237/image.png?width=595&height=187)


![App screenshot](https://media.discordapp.net/attachments/952706654464512030/1102317208849371147/image.png?width=1440&height=55)

j'ai juste à prendre la liste de 0 à 2505 regrouper 2 à 2 les éléments puis les convertir en hexa tout en respectant les conditions 


![App screenshot](https://cdn.discordapp.com/attachments/952706654464512030/1102318672388829288/image.png)



![App screenshot](https://cdn.discordapp.com/attachments/952706654464512030/1102318454821888180/image.png)

![App screenshot ](https://cdn.discordapp.com/attachments/952706654464512030/1102317958774145104/image.png)