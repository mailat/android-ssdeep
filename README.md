Android ssdeep
=============

Since there was no Android port of the ssdeep algorithm I considered will be great to have the algorith on the wild. So here it is today, 1 days before Droidcon :).

The ssdeep is a algorith, for computing and matching Context Triggered Piecewise Hashing values. It is based on a spam detector called spamsum by Andrews Trigdell. I translated in Java only 2 main functionalities:

* hashing of a binary file to receive a ssdeep hash ( for example: 98304:zj8h0BFpLzkjFaBv9MPC7HxN+IRZ2lxGSY696sGlAF:n843oFAePCPL0lxX/6sQI )
* comparing of 2 ssdeep hashes

The source-code is used in the development of DS Mobile Security for Android for implementing some functionality in the Anti-Virus module. Anti-Virus scans and blocks viruses, spyware, trojans, worms, bots and more before they infect your device and without straining the battery.

Three types of scan: quick, full and custom.Automatic scanning of apps downloaded from the marketplace.Real-time scan of files received over GPRS/Infrared/Bluetooth/Wi-Fi/USB-connection or while synchronizing with a PC. 

Contributing
------------

1. Fork it.
2. Create a branch (`git checkout -b my_android-ssdeep`)
3. Commit your changes (`git commit -am "Added better logic dude"`)
4. Push to the branch (`git push origin android-ssdeep`)
5. Open a [Pull Request][1]
6. Wait for aproval

[1]: http://github.com/github/android-ssdeep/pulls
