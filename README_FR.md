## Bienvenue sur bitcoinj
La bibliothèque bitcoinj est une implémentation du protocole Bitcoin en Java, qui permet de gérer un porte-monnaie et d’effectuer des transactions sans avoir besoin de créer une copie locale de Bitcoin. Une documentation et quelques exemples d’applications montrant comment s’en servir sont fournis.

## Technologies

* Java 6 pour les modules principaux, Java 8 pour le reste
* [Maven 3+](http://maven.apache.org/) - pour construire le projet
* [Google Protocol Buffers](https://github.com/google/protobuf) -  for use with serialization and hardware communications

## Démarrer
Pour démarrer, il est recommendé d’avoir les dernières version du JDK et de Maven installées. La tête de la branche master contient le dernier code de développement, et diverses versions de production sont fournies dans les branches des différentes fonctionnalités.

### Construire le projet à partir d’une ligne de commande
Pour effectuer une construction complète
```
mvn clean package
```
Ou alors, vous pouvez aussi executer la commande suivante
```
mvn site:site
```
pour générer un site web contenant les informations utiles comme les JavaDocs.
Les résultats sont situés dans le répertoire target.

### Construire à partir de l’IDE
Sinon, vous pouvez simplement importer le projet en utilisant votre IDE. Maven est intégré à [IntelliJ](http://www.jetbrains.com/idea/download/), qui dispose d’une édition communautaire gratuite. Utilisez simplement `File | Import Project` et localisez le fichier pom.xml dans la racine de l’arborescence source du projet cloné.

## Exemples d’applications
Ils peuvent être trouvés dans le module “examples”.

### Service de redirection
Cela va télécharger la chaîne de blocs et éventuellement imprimer une adresse Bitcoin qu'il a généré.
Si vous envoyez des pièces à cette adresse, il les transmettra à l'adresse que vous avez spécifiée.
```
  cd examples
  mvn exec:java -Dexec.mainClass=org.bitcoinj.examples.ForwardingService -Dexec.args="<insert a bitcoin address here>"
```
Notez que cet exemple d'application n'utilise pas de point de contrôle, donc la synchronisation de chaîne initiale sera assez lente. Vous pouvez créer une application qui démarre et effectue la synchronisation initiale beaucoup plus rapidement en incluant un fichier de points de contrôle; Voir la documentation pour plus d'informations sur cette technique.

## Et après ?
Maintenant, vous êtes prêts à [suivre le tutoriel](https://bitcoinj.github.io/getting-started).
