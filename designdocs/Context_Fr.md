# Architecture de l’API des classes contexts

Le document d’architecture décrit la classe Context qui est arrivé en version 0.13.

## Buts

- Centraliser divers bits de configuration qui sont dupliqués dans l'API, comme des répertoires pour 
  stocker des fichiers, la profondeur à laquelle un tx est considéré comme non ré organisable, les paramètres réseau choisis, etc.
- Simplifier la programmation de bitcoinj
- Eviter de vouloir surcharger la classe NetworkParameters avec des bits customisables et des parties de configurations diverses.
- Débloque différents bits qui ont rendu l’évolution de l’API difficile dans le but initiale d’éviter des modifications 
  trop nombreuses du code source par les développeurs. 

## Contexte

Depuis sa toute première version, bitcoinj possède le concept de “network parameters”. 
Une classe qui mêle diverses constantes et nombres magiques permettant de distinguer le réseau principal du réseau de test. 
Plus tard, à partir des paramètres, cette classe sera uniquement destinée aux tests unitaires et aux tests de régression locaux.

Cependant, contrairement à de nombreuses API, nous n'avons jamais eu de notion générale du contexte et, 
au fur et à mesure que la bibliothèque grandissait, nous avons fini par 
obtenir des doublons de paramètres et d’étranges dépendances entre plusieurs objets. 
Par exemple, plusieurs parties de la bibliothèque ont tendance à vouloir jeter des données une fois qu'une transaction est 
confirmée un nombre suffisant de fois.  Nous ne nous attendions pas à ce qu'elle soit réorganisée en dehors de la chaîne. 
En plus de cela, nous ne nous sommes pas mis d’accord sur l’étendue du nombre de confirmation à effectuer. 
Le Wallet stocke les fichiers, comme le font le blockstore et Orchid (support de ToR), mais il faut indiquer à chaque composant
où placer ces données de façon individuelle. Le problème s'aggrave lorsque nous sommes sous Android, les fichiers JAR n’existent pas 
et les données doivent être expédiées en tant que fichiers externes. De plus, sous Android, 
les composants qui veulent charger des fichiers de données doivent être configurés avec le chemin d'accès à ces fichiers, de façon 
individuelle. Malheureusement, il n'existe pas de liste répertoriant ce dont les composants ont besoin pour fonctionner.

Un autre problème est que l’API, étant largement utilisée, a besoin d’accepter que les composants explicites 
autorisent le code dépendant, à évoluer. Le composant le plus problématique étant : TransactionConfidence, 
par exemple TransactionConfidence.getDepthInBlocks(). 
Cette méthode ne prend pas de paramètres et a besoin tout particulièrement que l’objet Confidence, dans chaque transaction du 
Wallet, soit modifié à chaque block. Il est nécessaire de le faire, dans le but de mettre à jour son compteur interne. 
Une meilleure approche serait d’enregistrer la hauteur à laquelle il apparait, ainsi que de prendre l’AbstractBlockChain en 
paramètre (et/ou de prendre la hauteur de façon explicite) et d’effectuer la soustraction. Cependant, cette méthode est appelée à 
différents endroits, loin de la dernière référence, de la blockchain. 
Utiliser cette approche reviendrait à un changement pénible d'API.
Idéalement, nous devrions répartir ces changements au sein de plusieurs versions afin de laisser
le temps aux développeurs de mettre à jour leur code.

Un problème encore plus important est celui de Transaction.getConfidence().
Nous souhaiterions réécrire le Wallet pour qu’il ne stocke plus du tout les objets Transactions. 
Mais cette réécriture impliquerait un changement majeur de l’API, parce que les apps ont la fâcheuse tendance à vouloir savoir si elles peuvent avoir confiance dans une transaction.
Pour l’instant le seul moyen d’obtenir cette confiance, c’est d’utiliser la méthode getConfidence()
La classe TxConfidenceTable(anciennement MemoryPool) agit comme une hashmap globale d’un txhash vers un objet de confiance.
Néanmoins, nous ne pouvons pas ajuster le prototype de la méthode Transaction.getConfidence() pour en prendre un sans endommager 
beaucoup de code

La prolifération de variables globale rend difficile l’utilisation de plusieurs instances de bitcoinj aux développeurs.
Par exemple, pour effectuer une transaction inter chaine entre différentes cryptomonnaies.

Pour finir, plusieurs objets courants de bitcoinj ont besoin d’être inter connectés, de sorte qu’il soit difficile de savoir 
si la fonctionnalité complete fonctionne. Les constructeurs essayent de guider les développeurs, mais c’est une source 
fréquente d’erreur.

Nous pouvons résoudre ces problèmes en introduisant la notion d’un objet Context global utilisé à la même place et de la même 
manière que les NetworkParameters le sont aujourd’hui.


## Objet Context

La classe Context est très simple. C’est une classe immuable qui garde simplement des données de configuration et des références vers d’autres objets. 
Pour l’instant, nous n’autorisons pas la reconfiguration à la volée des données qu’elle stocke. 
Ceci étant pour simplifier l’implémentation du code.

## Alternatives considérées
Certaines bases de codes lorsqu’elles rencontrent le problème ci-dessus utilisent des containers d’injection de dépendance.
Ces parties du logiciel remplacent de façon efficace les mots clés « new » et gèrent toutes les créations d’objets par elles-mêmes, 
ainsi, elles connectent les objets entre eux en se basant sur des annotations et centralisent la configuration de manière explicite.

L’injection de dépendance semble une solution attractive, mais :

* Par l’expérience de l’utilisation de Guice chez Google, ceci me laisse à penser que son utilisation rendra le code confus, ce qui risque de détruire la fonction navigation de l’IDE et qui rendra la compréhension du code difficile pour un développeur inexpérimenté.
*	Guice change efficacement le langage Java, mais rend difficile la contribution au projet. Il pourrait y avoir des Frameworks d’injection de dépendances qui soient moins agressifs, mais je n’en connais pas.
*	L’injection de dépendances repose beaucoup sur la réflexion et sur le temps de génération du code, lesquelles nous souhaitons éviter pour des raisons de performances et pour éviter de compliquer la configuration Pro Guard et la transpilation.
*	L’injection de dépendances est effectivement juste une manière complexe et indirecte d’avoir un objet global Context : ceci permet ainsi d’avoir un code plus clair et d’éviter le besoin aux développeurs d’apprendre de nouvelles choses.

## Plan de Transition

NetworkParameters apparait partout dans l’API bitcoinj, et donc introduire Context aura un impact majeur sur cette dernière. 
Nous souhaitons garder le « churn » de l’API sous contrôle afin d’éviter de perdre des développeurs à cause d'améliorations difficiles.
Ainsi, Context sera répartie graduellement sur une ou deux versions.

Nous suivrons donc ces étapes :

 1. Context contient NetworkParameters, TxConfidenceTable et l’« event horizon» (le nombre de blocks après lequel on peut considérer qu’une réorganisation ne peut plus arriver).

 2. La construction de l’objet Context garde une référence sur lui-même dans un emplacement du Thread Local Storage. Une méthode statique est fournie, elle récupère ce dernier ainsi qu’elle récupère ou créer un nouveau Context. Cette seconde méthode est placée dans des constructeurs de classes importants comme le Wallet ou la block chain, et fournit une rétrocompatibilité aux développeurs. Un message d’avertissement s'affiche alertant les développeurs pour qu’ils mettent à jour leur code et pour qu'ils créent l’objet Context eux-mêmes. Tenter d’utiliser deux instances de la bibliothèque avec différents objets ou NetworkParameters sur le même thread pourrait créer des complications, voir empêcher la bibliothèque, à cette étape, de fonctionner.

 3. Les classes qui pour l’instant prennent un NetworkParameters sont étendues à de nouveaux constructeurs. Ces derniers prennent en paramètre un Context. Les anciens constructeurs vérifient simplement que le NetworkParameters, qu’ils auraient donné, correspondent correctement au Context. Ensuite, ils appellent les nouveaux constructeurs. S’il n’y a pas de correspondance, une exception est levée.

 4. Les notes de version décrivent comment mettre en place un context et le propager au sein des threads. La migration peut être effectuer par les développeurs à partir de la version 0.13.

 5.  Intérieurement, nous commençons à passer le context à travers les objets, qui en ont explicitement besoin, plutôt que de reposer sur l’espace de thread local storage.

 6. Nous marquons les constructeurs qui prennent, comme déprécié, un NetworkParameters grâce à la java docs. Puis, nous proposons aux développeurs, les constructeurs équivalents utilisant plutôt la classe Context.

 7. Dans quelques futurs versions, les méthodes dépréciées seront éventuellement supprimées, conjointement avec l’emplacement du Context thread local storage et avec l’automatisation de la propagation magique de l’inter-thread

En parallèle, la configuration globale va continuer à être déplacée dans la classe Context pour la rendre plus utile.

