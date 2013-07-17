Android ssdeep
=============

Since there was no Android port of the ssdeep algorithm I considered will be great to have the algorith on the wild. So here it is today, in the same day with the conference Droidcon in Berlin :).

The ssdeep is a algorith, for computing and matching "Context Triggered Piecewise Hashing" values. It is based on a spam detector called spamsum by Andrews Trigdell. I translated in Java only 2 main functionalities of the algorithm:

* hashing of a binary file to receive a ssdeep hash ( for example: 98304:zj8h0BFpLzkjFaBv9MPC7HxN+IRZ2lxGSY696sGlAF:n843oFAePCPL0lxX/6sQI )
* comparing of 2 ssdeep hashes to return the probability to be from the same source

The source-code is used in the development of DS Mobile Security for Android for implementing some functionality in the Anti-Virus module. Anti-Virus module scans and blocks viruses, spyware, trojans, worms, bots and more before they infect your device and without straining the battery and using a combination of patern-matching and ssdeep.

There are three types of scan: quick, full and custom (ssdeep is used in full and custom only) with automatic scanning of apps downloaded from the marketplace. Also the modules offers a real-time scan of files received over GPRS/Infrared/Bluetooth/Wi-Fi/USB-connection or while synchronizing with a PC. 

How can I contact you for more information?
-------------------------------------------
You can contact me using marius.mailat (at) gmail.com

How can I contribute?
---------------------

1. Fork it.
2. Create a branch (`git checkout -b my_android-ssdeep`)
3. Commit your changes (`git commit -am "Added better logic dude"`)
4. Push to the branch (`git push origin android-ssdeep`)
5. Open a [Pull Request][1]
6. Wait for aproval

License?
---------------------

Copyright (C) 2013 Marius Mailat
 
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
 
http://www.apache.org/licenses/LICENSE-2.0
 
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

[1]: http://github.com/github/android-ssdeep/pulls
