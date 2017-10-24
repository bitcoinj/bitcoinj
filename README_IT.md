[![Build Status](https://travis-ci.org/bitcoinj/bitcoinj.png?branch=master)](https://travis-ci.org/bitcoinj/bitcoinj)   [![Coverage Status](https://coveralls.io/repos/bitcoinj/bitcoinj/badge.png?branch=master)](https://coveralls.io/r/bitcoinj/bitcoinj?branch=master) 

[![Visit our IRC channel](https://kiwiirc.com/buttons/irc.freenode.net/bitcoinj.png)](https://kiwiirc.com/client/irc.freenode.net/bitcoinj)
### Benvenuti al bitcoinj

La libreria bitcoinj è una implementazione Java del protocollo Bitcoin, che permette di mantenere un portafoglio e di inviare/ricevere transazioni senza il bisogno di una copia di Bitcoin Core. Ciò viene dimostrato con una documentazione completa e alcuni esempi di applicazioni che mostrano come usarlo. 

### Technologie

* Java 6 per i moduli core, Java 8 per tutto il resto
* [Maven 3+](http://maven.apache.org) - per la realizzazione del progetto
* [Google Protocol Buffers](https://github.com/google/protobuf) – per l’utilizzo di serializzazione e di comunicazioni hardware

### Per iniziare

Per iniziare, la cosa migliore è avere installato l’ultima versione di JDK e di Maven. Il HEAD della sezione  `master` contiene l’ultimo codice di sviluppo e le sezioni “feature” provvedono il rilascio di diverse produzioni.

#### La progettazione del sistema dalla linea di commando

per svolgere una realizzazione completa
```
mvn clean package
```
Puoi anche eseguire 
```
mvn site:site
```
per generare un sito con informazioni utili come JavaDocs. 

I resultati si possono trovare sulla direttoria `target`.

#### Progettazione da un IDE 
In alternativa, si può importare il progetto usando il vostro IDE. [IntelliJ](http://www.jetbrains.com/idea/download/) ha l’integrazione Maven compresa e ha disponibile una Community Edition. Basta utilizzare `File | Import Project` e localizzare `pom.xml` nella fonte dell progetto clonato. 

### Esempi di applicazioni 
Questi si trovano nel modulo `examples`. 

#### Servizio di inoltro 
Questo permetterà il download di block chain ed eventualmente stamperà un indirizzo Bitocin che è stato generato.
Se puoi inviare coins all’indirizzo, questo li invierà all’indirizzo che hai specificato. 

```
  cd examples
  mvn exec:java -Dexec.mainClass=org.bitcoinj.examples.ForwardingService -Dexec.args="<insert a bitcoin address here>"
```

Nota bene che questo esempio *non utilizza checkpointing*, quindi la catena di sincronizzazione iniziale sarà lenta. Si può fare un app che si avvia ed esegue la sincronizzazione iniziale molto più velocemente includendo un file checkpoints. Veda la documentazione per maggiori informazioni su questa tecnica. 
### E dopo?  
Adesso siete in grado di seguire il [tutorial](https://bitcoinj.github.io/getting-started). 
