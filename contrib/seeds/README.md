### Seeds ###

Script to generate seed IP address data files from sipa's DNS seed data. (To see how this is handled in Bitcoin Core, see that [README](https://github.com/bitcoin/bitcoin/tree/master/contrib/seeds).)

The Gradle script (which will probably be replaced by a Python script) does the following:

1. Download [http://bitcoin.sipa.be/seeds.txt](http://bitcoin.sipa.be/seeds.txt) to ```build/seeds.txt```
1. Filter the top 600 valid IPv4 or IPv6 addresses in to ```build/org.bitcoin.production-seeds.txt```
1. Copy the following files to ```../../core/src/main/resources/com/google/bitcoin/net/discovery```

        build/org.bitcoin.production-seeds.txt
        data/org.bitcoin.test-seeds.txt
        data/com.google.bitcoin.unittest-seeds.txt

Note that these seed files use the ID string from the ```NetworkParameters``` class with a ```-seeds.txt``` suffix.

The files in the ```build``` directory are *not* checked in to Git, whereas the files in the ```data``` directory are manually created and checked in to Git.

The copies in ```../../core/src/main/resources/com/google/bitcoin/net/discovery``` *are* checked in to Git, because we want the main build to run without using any scripts from this (```contrib/seeds```) directory.


