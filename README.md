# AdGuard content blocking library

Pure GO library that implements AdGuard filtering rules syntax.

You can learn more about AdGuard filtering rules syntax from [this article](https://kb.adguard.com/en/general/how-to-create-your-own-ad-filters).

#### TODO:

* [X] Basic filtering rules
    * [X] Core blocking syntax
    * [X] Basic engine
* [X] Benchmark basic rules matching
* [ ] Hosts matching rules
    * [ ] /etc/hosts matching
    * [ ] memory optimizations?  
* [ ] CSS rules
    * [ ] Proper CSS rules validation
* [ ] Advanced modifiers part 1
    * [ ] $csp
    * [ ] $badfilter
    * [ ] $important
* [ ] ExtCSS rules
* [ ] Scriptlet rules
* [ ] JS rules
* [ ] HTML filtering rules
* [ ] Advanced modifiers part 2
    * [ ] $replace
    * [ ] $cookie