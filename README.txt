* Directory Organization

  * ~fasguard-ad-host-peering~:  Host peering anomaly detector
    (reference sensor).
  * ~libfasguard_sensor~:  Library used by detector designers to
    format captured packets (or log entries or HTTP headers or...) as
    STIX/CybOX XML records and send them to the signature generation
    system.
  * ~libfasguard_collector~:  Library used to receive the XML and turn
    it into callbacks.
  * ~fasguard-asg~:  Program that takes STIX/CybOX XML and benign
    packet data and outputs IDS rules for Suricata.
    * ~fasguard-asg/bloom~:  Tools to take benign traffic and turn it
      into n-gram Bloom filters
    * ~fasguard-asg/sig-gen~:  Takes input from ~libfasguard_collector~
      and outputs strings for use in IDS rules.
    * ~fasguard-asg/sig-filter~:  Filters the output from ~sig-gen~
      using benign traffic Bloom filters.
    * ~fasguard-asg/rule-gen~:  Generates IDS rules from the output of
      ~sig-filter~.
  * ~libfasguard_rule_tx~:  Library that uses TAXII to send IDS rules
    to Suricata
  * ~libfasguard_rule_rx~:  Library that receives the IDS rules over
    TAXII and provides them to Suricata (or some other program).
  * ~suricata~:  Friendly fork of Suricata that we can modify to
    integrate with ~libfasguard_rule_rx~
  * ~data~:  Collection of sample attack packets, benign traffic,
    populated Bloom filters, etc.

For an overview of how these components fit together, see Section
[[sec:arch]].

* System Architecture
<<sec:arch>>

TODO

** Automatic Signature Generator

TODO

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
