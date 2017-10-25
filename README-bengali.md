[![Build Status](https://travis-ci.org/bitcoinj/bitcoinj.png?branch=master)](https://travis-ci.org/bitcoinj/bitcoinj)   [![Coverage Status](https://coveralls.io/repos/bitcoinj/bitcoinj/badge.png?branch=master)](https://coveralls.io/r/bitcoinj/bitcoinj?branch=master) 

[![Visit our IRC channel](https://kiwiirc.com/buttons/irc.freenode.net/bitcoinj.png)](https://kiwiirc.com/client/irc.freenode.net/bitcoinj)

### বিটকয়েনে স্বাগতম

বিটকয়েন-জি লাইব্রেরি বিটকয়েন প্রোটোকলের একটি জাভা বাস্তবায়ন যা এটি একটি ওয়ালেট বজায় রাখার এবং বিটকয়েন কোরের একটি স্থানীয় প্রতিলিপি ব্যতীত লেনদেন / প্রেরণ করার অনুমতি দেয়। এটির সাথে আছে পূর্ণ ডকুমেন্টেশন এবং কিছু উদাহরণ অ্যাপ্লিকেশন যা এটি ব্যবহার করে কিভাবে দেখাচ্ছেে।

### প্রযুক্তি

* জাভা ৬ কোর মডিউল জন্য, জাভা ৮ বাকি সবকিছুর জন্য
* [মাভেন ৩+](http://maven.apache.org) - প্রকল্পের নির্মাণের জন্য
* [গুগল প্রোটোকল বাফার্স](https://github.com/google/protobuf) - সিরিয়ালাইজেশন এবং হার্ডওয়্যার যোগাযোগের সাথে ব্যবহারের জন্য

### শুরু হচ্ছে

শুরু করার জন্য, সর্বশেষ JDK এবং মাভেন ইনস্টল করা সবচেয়ে ভাল। `মাস্টার` শাখার প্রধান সর্বশেষ উন্নয়ন কোড এবং বিভিন্ন প্রজেক্টের রিলিজগুলি বৈশিষ্ট্য শাখায় সরবরাহ করা হয়।

#### কমান্ড লাইন থেকে নির্মাণ

একটি সম্পূর্ণ বিল্ড ব্যবহার সঞ্চালন করতে
```
mvn clean package
```
আপনি চালাতে পারেন
```
mvn site:site
```
জাভা ডক্সের মত দরকারী তথ্য সহ একটি ওয়েবসাইট তৈরি করতে.

আউটপুট `target` ডিরেক্টরির অধীনে আছে।

#### IDE থেকে নির্মাণ

বিকল্পভাবে, শুধুমাত্র আপনার IDE ব্যবহার করে এই প্রকল্পটি আমদানি করুন. [IntelliJ](http://www.jetbrains.com/idea/download/) has Maven integration built-in and has a free Community Edition. সহজভাবে ব্যবহার করুন `File | Import Project` and locate the `pom.xml` ক্লোন প্রজেক্টের সোর্স ট্রি মূল অংশে

### উদাহরণ অ্যাপ্লিকেশন

এই `examples` মডিউল মধ্যে পাওয়া যায়।

#### ফরওয়ার্ডিং সেবা

এটি ব্লক শৃঙ্খলাটি ডাউনলোড করবে এবং অবশেষে একটি বিটকয়েন ঠিকানা প্রকাশ করবে যা এটি তৈরি করেছে।

আপনি যদি সেই ঠিকানাতে মুদ্রা প্রেরণ করেন তবে এটি আপনার ঠিকানাটি নির্দিষ্ট করে দেবে।

```
  cd examples
  mvn exec:java -Dexec.mainClass=org.bitcoinj.examples.ForwardingService -Dexec.args="<insert a bitcoin address here>"
```

লক্ষ্য করুন যে এই উদাহরণ অ্যাপ্লিকেশন * চেকপয়েন্টিং * ব্যবহার করে না, তাই প্রাথমিক শিকল সঙ্কোচটি বেশ ধীর হবে। আপনি একটি অ্যাপ্লিকেশন তৈরি করতে পারেন যা শুরু করে এবং একটি চেকপয়েন্ট ফাইল সহ প্রাথমিক সিকিউরিটি দ্রুততর করে; এই কৌশল আরও তথ্যর জন্য ডকুমেন্টেশন দেখুন

### পরবর্তী কোথায়?

এখন আপনি প্রস্তুত [টিউটোরিয়াল অনুসরণ করুন](https://bitcoinj.github.io/getting-started).
