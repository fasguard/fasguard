* Directory Organization

  * ~fasguard-benign-traffic-collection~

    Tools to collect live network traffic and save it in a form
    suitable for consumption by ~fasguard-benign-traffic-compression~.

  * ~fasguard-benign-traffic-compression~

    Tools to take the raw benign traffic collected by the tools in
    ~fasguard-benign-traffic-collection~ and turn it into n-gram Bloom
    filters.

  * ~fasguard-ad-host-peering~

    Host peering anomaly detector (reference sensor).

  * ~fasguard-ad-*~

    Prefix reserved for other anomaly detectors.

  * ~fasguardlib-ad-common~

    Schema definition for the XML representation of the "bad" traffic
    coming from the anomaly detectors.

  * ~fasguardlib-ad-tx~

    Library used by detector designers to format captured packets (or
    log entries or HTTP headers or...) as STIX/CybOX XML records and
    send them to the signature generation system.

  * ~fasguardlib-ad-rx~

    Library that receives and parses the XML coming from the anomaly
    detectors.

  * ~fasguard-asg~

    Program that takes "bad" and benign packet data and outputs IDS
    rules for Suricata.  It is divided into these sub-components:

    * ~fasguard-asg/sig-gen~

      Takes input from ~fasguardlib-ad-rx~ and outputs strings for use
      in IDS rules.

    * ~fasguard-asg/sig-filter~

      Filters benign strings from the output of ~sig-gen~ using the
      benign traffic Bloom filters that are created by
      ~fasguard-benign-traffic-compression~.

    * ~fasguard-asg/rule-gen~

      Generates IDS rules suitable for Suricata from the output of
      ~sig-filter~.

  * ~fasguardlib-rule-common~

    Schema definition for XML-wrapped Suricata IDS rules.

  * ~fasguardlib-rule-tx~

    Library that generates XML-wrapped Suricata IDS rules and sends
    them to Suricata via TAXII.

  * ~fasguardlib-rule-rx~

    Library that receives and parses the IDS rules coming from
    ~fasguardlib-rule-tx~ and provides them to Suricata (or some other
    program).

  * ~suricata~

    Friendly fork of Suricata that we can modify to integrate with
    ~fasguardlib-rule-rx~.

  * ~fasguard-samples~

    Collection of sample attack packets, benign traffic, populated
    Bloom filters, etc.

  * ~fasguardlib-bloom~

    Shared library for creating and using Bloom filters.

For an overview of how these components fit together, see Section
[[sec:arch]].

* System Architecture
<<sec:arch>>

TODO: add prose

#+BEGIN_SRC ditaa :file README_arch.png :cmdline -E
                      live traffic stream or recorded archive
                                        |
            +--------------------+------+----------+-----------------+
            |                    |                 |                 |
            v                    v                 v                 v
  /-------------------\   /--------------\  /--------------\  /--------------\
  | fasguard‐ad‐host‐ |   |    other     |  |    other     |  |    legacy    |
  |  peering sensor   |   |    sensor    |  |    sensor    |  |    sensor    |
  +-------------------+   +--------------+  +--------------+  +--------------+
  |    fasguardlib‐   |   | fasguardlib‐ |  | fasguardlib‐ |  | fasguardlib‐ |
  |       ad‐tx       |   |    ad‐tx     |  |    ad‐tx     |  |    ad‐tx     |
  \----------+--------/   \------+-------/  \------+-------/  \------+-------/
            |                    |                 |                 |
            |                    |                 +--------+--------+
            |                    | "bad" packet data (STIX) |
            |                    |                          v
            |                    |          /------------------------------\
            |                    |          |       fasguardlib‐ad‐rx      |
            |                    |          +------------------------------+
            |                    |          | aggregator/legacy translator |
            |                    |          +------------------------------+
            |                    |          |       fasguardlib‐ad‐tx      |
            |                    |          \---------------+--------------/
            |                    |                          |
            +--------------------+--------------------------+
                                 |
                                 v
                 /-------------------------------\
                 |       fasguardlib‐ad‐rx       |
                 +-------------------------------+
                 |         fasguard‐asg          |
                 | automatic signature generator |<---- "good" packet data
                 |        (detailed below)       |      (detailed below)
                 +-------------------------------+
                 |      fasguardlib‐rule‐tx      |
                 \---------------+---------------/
                                 |
                 +---------------+------------+
                 |     IDS rules (TAXII)      |
                 v                            v
      /---------------------\      /---------------------\
      | fasguardlib‐rule‐rx |      | fasguardlib‐rule‐rx |
      +---------------------+      +---------------------+
      |      Suricata       |      |  rule distributor   |
      \---------------------/      +---------------------+
                                   | fasguardlib‐rule‐tx |
                                   \----------+----------/
                                              | IDS rules (TAXII)
                +------------------------+----+-------------------+
                |                        |                        |
                v                        v                        v
     /---------------------\  /---------------------\  /---------------------\
     | fasguardlib‐rule‐rx |  | fasguardlib‐rule‐rx |  | fasguardlib‐rule‐rx |
     +---------------------+  +---------------------+  +---------------------+
     |      Suricata       |  |      Suricata       |  |      Suricata       |
     \---------------------/  \---------------------/  \---------------------/
#+END_SRC

** Automatic Signature Generator

TODO: add prose

#+BEGIN_SRC ditaa :file README_arch_asg.png :cmdline -E
   "bad" packet data (STIX/CybOX)
                 |
   /-------------|--------------\
   |             |              |
   |             v              |
   |      fasguardlib‐ad‐rx     |
   |             |              |
   +-------------|--------------+
   |fasguard‐asg |              |
   |             v              |
   |  /----------------------\  |
   |  | signature generation |  |
   |  |      (sig‐gen)       |  |                           live or recorded
   |  \----------+-----------/  |                            "good" packets
   |             |              |                                  |
   |             v              |                                  v
   |     /----------------\     |  /------------------\   /------------------\
   |     | false positive |     |  | fasguard‐benign‐ |   | fasguard‐benign‐ |
   |     |    reduction   |<----+--+     traffic‐     |<--+     traffic‐     |
   |     |  (sig‐filter)  |     |  |   compression    |   |    collection    |
   |     \-------+--------/     |  \------------------/   \------------------/
   |             |              |
   |             v              |
   |  /---------------------\   |
   |  | IDS rule generation |   |
   |  |      (rule‐gen)     |   |
   |  \----------+----------/   |
   |             |              |
   +-------------|--------------+
   |             |              |
   |             v              |
   |     fasguardlib‐rule‐tx    |
   |             |              |
   \-------------|--------------/
                 |
                 v
         TAXII to Suricata
#+END_SRC

** Component Details

TODO

* emacs org-mode settings                                          :noexport:
  :PROPERTIES:
  :VISIBILITY: folded
  :END:
#+STARTUP: showall
#+OPTIONS: toc:nil ^:{} H:10
one inch margins on letter paper:
#+LATEX_HEADER: \usepackage[letterpaper,margin=1in,twoside]{geometry}%
get rid of the ugly red borders around clickable links:
#+LATEX_HEADER: \hypersetup{pdfborder={0 0 0}}

Local Variables:
mode:org
End:
